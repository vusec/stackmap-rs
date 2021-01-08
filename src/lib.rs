mod parser;

use std::mem;

use fallible_iterator::FallibleIterator;
use nom::Finish;
use snafu::Snafu;

#[derive(Debug, Clone)]
pub struct LLVMStackMaps<'a> {
    section_data: &'a [u8],
}

impl<'a> LLVMStackMaps<'a> {
    pub fn new(section_data: &'a [u8]) -> Self {
        LLVMStackMaps { section_data }
    }

    pub fn stack_maps(&self) -> StackMapsIter<'a> {
        StackMapsIter {
            data: self.section_data,
        }
    }
}

pub struct StackMapsIter<'a> {
    data: &'a [u8],
}

impl<'a> FallibleIterator for StackMapsIter<'a> {
    type Item = StackMap<'a>;
    type Error = Error<'a>;

    fn next(&mut self) -> ::core::result::Result<Option<Self::Item>, Self::Error> {
        if self.data.is_empty() {
            return Ok(None);
        }

        match parser::parse_stack_map(self.data).finish() {
            Ok((rest, next_stack_map)) => {
                self.data = rest;
                Ok(Some(next_stack_map))
            }
            Err(error) => Err(error),
        }
    }
}

type StackMapVersion = u8;

#[derive(Debug, Clone)]
pub struct StackMap<'a> {
    version: StackMapVersion,
    num_functions: u32,

    functions: &'a [u8],
    constants: &'a [u64],
    record_slices: Vec<&'a [u8]>, // Records have variable length, so they cannot be lazily parsed
}

impl<'a> StackMap<'a> {
    pub fn version(&self) -> StackMapVersion {
        self.version
    }

    pub fn functions(&self) -> FunctionsIter {
        FunctionsIter {
            data: self.functions,
            record_slices: self.record_slices.clone(),
            remaining_functions: self.num_functions as usize,
            constants: self.constants,
        }
    }
}

pub struct FunctionsIter<'a> {
    data: &'a [u8],
    record_slices: Vec<&'a [u8]>,
    constants: &'a [u64],
    remaining_functions: usize,
}

impl<'a> FallibleIterator for FunctionsIter<'a> {
    type Item = Function<'a>;
    type Error = Error<'a>;

    fn next(&mut self) -> ::core::result::Result<Option<Self::Item>, Self::Error> {
        if self.data.is_empty() {
            // The functions should contain all the records
            if self.record_slices.is_empty() {
                return Ok(None);
            } else {
                return FunctionRecordMismatch.fail();
            }
        }

        match parser::parse_function((
            self.data,
            mem::take(&mut self.record_slices),
            self.constants,
        ))
        .finish()
        {
            Ok(((rest_data, rest_record_slices, _), next_function)) => {
                self.data = rest_data;
                self.record_slices = rest_record_slices;
                self.remaining_functions -= 1;
                Ok(Some(next_function))
            }
            Err(error) => Err(error),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining_functions, Some(self.remaining_functions))
    }
}

#[derive(Debug, Clone)]
pub struct Function<'a> {
    address: u64,
    stack_size: u64,

    records: Vec<&'a [u8]>,
    constants: &'a [u64],
}

impl<'a> Function<'a> {
    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn stack_size(&self) -> u64 {
        self.stack_size
    }

    pub fn records(&'a self) -> RecordsIter<'a> {
        RecordsIter {
            records_iter: self.records.iter(),
            remaining_records: self.records.len(),
            constants: self.constants,
        }
    }
}

pub struct RecordsIter<'a> {
    records_iter: std::slice::Iter<'a, &'a [u8]>,
    constants: &'a [u64],
    remaining_records: usize,
}

impl<'a> FallibleIterator for RecordsIter<'a> {
    type Item = Record<'a>;
    type Error = Error<'a>;

    fn next(&mut self) -> ::core::result::Result<Option<Self::Item>, Self::Error> {
        let record_slice = match self.records_iter.next() {
            Some(record_slice) => record_slice,
            None => return Ok(None),
        };

        match parser::parse_record((record_slice, self.constants)).finish() {
            Ok(((rest, _), next_record)) => {
                assert!(rest.is_empty()); // This record slice has already been parsed
                self.remaining_records -= 1;
                Ok(Some(next_record))
            }
            Err(error) => Err(error),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining_records, Some(self.remaining_records))
    }
}

#[derive(Debug, Clone)]
pub struct Record<'a> {
    patch_point_id: u64,
    instruction_offset: u32,
    num_locations: u16,
    num_live_outs: u16,

    locations: &'a [u8],
    live_outs: &'a [u8],
    constants: &'a [u64],
}

impl<'a> Record<'a> {
    pub fn patch_point_id(&self) -> u64 {
        self.patch_point_id
    }

    pub fn instruction_offset(&self) -> u32 {
        self.instruction_offset
    }

    pub fn locations(&self) -> LocationsIter<'a> {
        LocationsIter {
            data: self.locations,
            constants: self.constants,
            remaining_locations: self.num_locations as usize,
        }
    }

    pub fn live_outs(&self) -> LiveOutsIter<'a> {
        LiveOutsIter {
            data: self.live_outs,
            remaining_live_outs: self.num_live_outs as usize,
        }
    }
}

pub struct LocationsIter<'a> {
    data: &'a [u8],
    constants: &'a [u64],
    remaining_locations: usize,
}

impl<'a> FallibleIterator for LocationsIter<'a> {
    type Item = Location;
    type Error = Error<'a>;

    fn next(&mut self) -> ::core::result::Result<Option<Self::Item>, Self::Error> {
        if self.data.is_empty() {
            return Ok(None);
        }

        match parser::parse_location((self.data, self.constants)).finish() {
            Ok(((rest, _), next_location)) => {
                self.data = rest;
                self.remaining_locations -= 1;
                Ok(Some(next_location))
            }
            Err(error) => Err(error),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining_locations, Some(self.remaining_locations))
    }
}

pub struct LiveOutsIter<'a> {
    data: &'a [u8],
    remaining_live_outs: usize,
}

impl<'a> FallibleIterator for LiveOutsIter<'a> {
    type Item = LiveOut;
    type Error = Error<'a>;

    fn next(&mut self) -> ::core::result::Result<Option<Self::Item>, Self::Error> {
        if self.data.is_empty() {
            return Ok(None);
        }

        match parser::parse_live_out(self.data).finish() {
            Ok((rest, next_live_out)) => {
                self.data = rest;
                self.remaining_live_outs -= 1;
                Ok(Some(next_live_out))
            }
            Err(error) => Err(error),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining_live_outs, Some(self.remaining_live_outs))
    }
}

pub type DwarfRegNum = u16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocationKind {
    Register(DwarfRegNum),
    Direct { register: DwarfRegNum, offset: i32 },
    Indirect { register: DwarfRegNum, offset: i32 },
    Constant(u64),
}

#[derive(Debug, Clone)]
pub struct Location {
    kind: LocationKind,
    size: u16,
}

impl Location {
    pub fn kind(&self) -> &LocationKind {
        &self.kind
    }

    pub fn size(&self) -> u16 {
        self.size
    }
}

#[derive(Debug, Clone)]
pub struct LiveOut {
    dwarf_reg_num: DwarfRegNum,
    size: u8,
}

impl LiveOut {
    pub fn dwarf_reg_num(&self) -> DwarfRegNum {
        self.dwarf_reg_num
    }

    pub fn size(&self) -> u8 {
        self.size
    }
}
#[derive(Debug, Snafu)]
pub enum Error<'a> {
    ParserError {
        input: &'a [u8],
        kind: nom::error::ErrorKind,
    },
    UnsupportedVersion,
    MalformedHeader,
    FunctionRecordMismatch,
    MalformedReserved,
    InvalidConstantIndex {
        index: i32,
    },
    InvalidLocationKind {
        invalid_kind: u8,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_stackmap() {
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let section = LLVMStackMaps::new(data);
        let stack_maps: Vec<_> = section.stack_maps().collect().unwrap();
        assert_eq!(stack_maps.len(), 1);
        assert_eq!(stack_maps[0].version(), 3);
    }

    #[test]
    fn single_function_record_location() {
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0xc0, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x02, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00, 0x00, 0xf6, 0xff, 0xff, 0xff, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let section = LLVMStackMaps::new(data);
        let stack_maps: Vec<_> = section.stack_maps().collect().unwrap();
        assert_eq!(stack_maps.len(), 1);
        assert_eq!(stack_maps[0].version(), 3);

        let functions: Vec<_> = stack_maps[0].functions().collect().unwrap();
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].address(), 0x11c0);
        assert_eq!(functions[0].stack_size(), 88);

        let records: Vec<_> = functions[0].records().collect().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].patch_point_id(), 42);
        assert_eq!(records[0].instruction_offset(), 15);

        let locations: Vec<_> = records[0].locations().collect().unwrap();
        assert_eq!(locations.len(), 1);
        assert_eq!(
            *locations[0].kind(),
            LocationKind::Direct {
                register: 6,
                offset: -10
            }
        );
        assert_eq!(locations[0].size(), 8);

        let live_outs: Vec<_> = records[0].live_outs().collect().unwrap();
        assert!(live_outs.is_empty());
    }
}
