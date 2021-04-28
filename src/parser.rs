use crate::{Error, Function, LiveOut, Location, LocationKind, Record, StackMap};

use std::{mem::size_of, slice};

use nom::{
    bytes::complete::take,
    number::complete::{le_i32, le_u16, le_u32, le_u64, le_u8},
    sequence::tuple,
};

type IResult<I, O> = nom::IResult<I, O, crate::Error>;

const STACK_SIZE_RECORD_SIZE: usize = size_of::<u64>() * 3;
const CONSTANT_SIZE: usize = size_of::<u64>();
const LOCATION_SIZE: usize = size_of::<u8>() * 2 + size_of::<u16>() * 3 + size_of::<i32>();
const LIVE_OUT_SIZE: usize = size_of::<u16>() + size_of::<u8>() * 2;
const ALIGNMENT_BYTES: usize = 8;

impl<'a, T> nom::error::ParseError<(&'a [u8], T)> for crate::Error {
    fn from_error_kind(input: (&'a [u8], T), kind: nom::error::ErrorKind) -> Self {
        Self::ParserError {
            input: input.0[..8].into(),
            kind,
        }
    }

    fn append(_: (&[u8], T), _: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> nom::error::ParseError<&'a [u8]> for crate::Error {
    fn from_error_kind(input: &'a [u8], kind: nom::error::ErrorKind) -> Self {
        Self::ParserError {
            input: input[..8].into(),
            kind,
        }
    }

    fn append(_: &[u8], _: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

fn parse_header(input: &[u8]) -> IResult<&[u8], crate::StackMapVersion> {
    let (rest, (version, zeroed_1, zeroed_2)) = tuple((le_u8, le_u8, le_u16))(input)?;

    if zeroed_1 != 0 || zeroed_2 != 0 {
        return Err(nom::Err::Failure(crate::Error::MalformedHeader));
    }

    Ok((rest, version))
}

const fn padding_size(parsed_bytes: usize, alignment_bytes: usize) -> usize {
    (alignment_bytes - (parsed_bytes % alignment_bytes)) % alignment_bytes
}

pub(crate) fn parse_record<'a>(
    input_and_constants: (&'a [u8], &'a [u64]),
) -> IResult<(&'a [u8], &'a [u64]), Record<'a>> {
    // The `constants` are just passed on without being changed
    let (input, constants) = input_and_constants;

    let (rest, (patch_point_id, instruction_offset, _, num_locations)) =
        tuple((le_u64, le_u32, le_u16, le_u16))(input)?;

    let locations_bytes = num_locations as usize * LOCATION_SIZE;
    let (rest, locations) = take(locations_bytes)(rest)?;
    let parsed_bytes = input.len() - rest.len();
    let (rest, _) = take(padding_size(parsed_bytes, ALIGNMENT_BYTES))(rest)?;

    let (rest, _) = le_u16(rest)?;
    let (rest, num_live_outs) = le_u16(rest)?;

    let live_outs_bytes = num_live_outs as usize * LIVE_OUT_SIZE;
    let (rest, live_outs) = take(live_outs_bytes)(rest)?;
    let parsed_bytes = input.len() - rest.len();
    let (rest, _) = take(padding_size(parsed_bytes, ALIGNMENT_BYTES))(rest)?;

    Ok((
        (rest, constants),
        Record {
            patch_point_id,
            instruction_offset,
            num_locations,
            num_live_outs,
            locations,
            live_outs,
            constants,
        },
    ))
}

pub(crate) fn parse_stack_map(input: &[u8]) -> IResult<&[u8], StackMap> {
    let (rest, version) = parse_header(input)?;
    if version != 3 {
        return Err(nom::Err::Failure(Error::UnsupportedVersion));
    }

    let (rest, (num_functions, num_constants, num_records)) =
        tuple((le_u32, le_u32, le_u32))(rest)?;

    let (rest, functions) = take(num_functions as usize * STACK_SIZE_RECORD_SIZE)(rest)?;

    let (rest, constants_bytes) = take(num_constants as usize * CONSTANT_SIZE)(rest)?;
    let constants = unsafe {
        slice::from_raw_parts(
            constants_bytes.as_ptr().cast::<u64>(),
            num_constants as usize,
        )
    };

    let mut record_slices = Vec::with_capacity(num_records as usize);
    let mut rest = rest;
    for _ in 0..num_records {
        let ((new_rest, _), _) = parse_record((rest, constants))?;

        let record_size = rest.len() - new_rest.len();
        let (record_slice, _) = rest.split_at(record_size);

        record_slices.push(record_slice);
        rest = new_rest;
    }

    Ok((
        rest,
        StackMap {
            version,
            num_functions,
            functions,
            record_slices,
            constants,
        },
    ))
}

type InputRecordsConstantsTuple<'a> = (&'a [u8], Vec<&'a [u8]>, &'a [u64]);
pub(crate) fn parse_function(
    input_and_records_and_constants: InputRecordsConstantsTuple,
) -> IResult<InputRecordsConstantsTuple, Function> {
    let (input, mut records, constants) = input_and_records_and_constants;
    let (rest_input, (address, stack_size, record_count)) = tuple((le_u64, le_u64, le_u64))(input)?;
    let rest_records = records.split_off(record_count as usize);

    Ok((
        (rest_input, rest_records, constants),
        Function {
            address,
            stack_size,
            records,
            constants,
        },
    ))
}

pub(crate) fn parse_location<'a>(
    input_and_constants: (&'a [u8], &'a [u64]),
) -> IResult<(&'a [u8], &'a [u64]), Location> {
    let (input, constants) = input_and_constants;

    let (rest, (loc_kind, zeroed_1, size, dwarf_reg_num, zeroed_2, offset_or_small_const)) =
        tuple((le_u8, le_u8, le_u16, le_u16, le_u16, le_i32))(input)?;

    if zeroed_1 != 0 || zeroed_2 != 0 {
        return Err(nom::Err::Failure(crate::Error::MalformedReserved));
    }

    let kind = match loc_kind {
        1 => LocationKind::Register(dwarf_reg_num),
        2 => LocationKind::Direct {
            register: dwarf_reg_num,
            offset: offset_or_small_const as isize,
        },
        3 => LocationKind::Indirect {
            register: dwarf_reg_num,
            offset: offset_or_small_const as isize,
        },
        4 => LocationKind::Constant(offset_or_small_const as u64),
        5 => {
            if offset_or_small_const < 0 || offset_or_small_const as usize >= constants.len() {
                return Err(nom::Err::Failure(crate::Error::InvalidConstantIndex {
                    index: offset_or_small_const,
                }));
            }
            LocationKind::Constant(constants[offset_or_small_const as usize])
        }
        invalid_kind => {
            return Err(nom::Err::Failure(crate::Error::InvalidLocationKind {
                invalid_kind,
            }));
        }
    };

    Ok(((rest, constants), Location { kind, size }))
}

pub(crate) fn parse_live_out(input: &[u8]) -> IResult<&[u8], LiveOut> {
    let (rest, (dwarf_reg_num, _, size)) = tuple((le_u16, le_u8, le_u8))(input)?;

    Ok((
        rest,
        LiveOut {
            dwarf_reg_num,
            size,
        },
    ))
}
