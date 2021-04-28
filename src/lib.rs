mod parser;

use std::mem;

use fallible_iterator::FallibleIterator;
use nom::Finish;
use snafu::Snafu;

#[derive(Debug, Clone)]
pub struct LLVMStackMaps<'input> {
    section_data: &'input [u8],
}

impl<'input> LLVMStackMaps<'input> {
    pub fn new(section_data: &'input [u8]) -> Self {
        Self { section_data }
    }

    pub fn stack_maps(&self) -> StackMapsIter<'input> {
        StackMapsIter {
            data: self.section_data,
        }
    }
}

pub struct StackMapsIter<'input> {
    data: &'input [u8],
}

impl<'input> FallibleIterator for StackMapsIter<'input> {
    type Item = StackMap<'input>;
    type Error = Error;

    fn next(&mut self) -> Result<'input, Option<Self::Item>> {
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

pub type StackMapVersion = u8;

#[derive(Debug, Clone)]
pub struct StackMap<'input> {
    version: StackMapVersion,
    num_functions: u32,

    functions: &'input [u8],
    constants: &'input [u64],
    record_slices: Vec<&'input [u8]>, // Records have variable length, so they cannot be lazily parsed
}

impl<'input> StackMap<'input> {
    pub fn version(&self) -> StackMapVersion {
        self.version
    }

    pub fn num_functions(&self) -> usize {
        self.num_functions as usize
    }

    pub fn functions(&self) -> FunctionsIter<'input> {
        FunctionsIter {
            data: self.functions,
            record_slices: self.record_slices.clone(),
            remaining_functions: self.num_functions as usize,
            constants: self.constants,
        }
    }
}

pub struct FunctionsIter<'input> {
    data: &'input [u8],
    record_slices: Vec<&'input [u8]>,
    constants: &'input [u64],
    remaining_functions: usize,
}

impl<'input> FallibleIterator for FunctionsIter<'input> {
    type Item = Function<'input>;
    type Error = Error;

    fn next(&mut self) -> Result<'input, Option<Self::Item>> {
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
pub struct Function<'input> {
    address: u64,
    stack_size: u64,

    records: Vec<&'input [u8]>,
    constants: &'input [u64],
}

impl<'input> Function<'input> {
    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn stack_size(&self) -> usize {
        self.stack_size as usize
    }

    pub fn num_records(&self) -> usize {
        self.records.len()
    }

    pub fn records<'me>(&'me self) -> RecordsIter<'me, 'input> {
        RecordsIter {
            records_iter: self.records.iter(),
            remaining_records: self.records.len(),
            constants: self.constants,
        }
    }
}

pub struct RecordsIter<'function, 'input> {
    records_iter: std::slice::Iter<'function, &'input [u8]>,
    constants: &'input [u64],
    remaining_records: usize,
}

impl<'function, 'input> FallibleIterator for RecordsIter<'function, 'input> {
    type Item = Record<'input>;
    type Error = Error;

    fn next(&mut self) -> Result<'input, Option<Self::Item>> {
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
pub struct Record<'input> {
    patch_point_id: u64,
    instruction_offset: u32,
    num_locations: u16,
    num_live_outs: u16,

    locations: &'input [u8],
    live_outs: &'input [u8],
    constants: &'input [u64],
}

impl<'input> Record<'input> {
    pub fn patch_point_id(&self) -> u64 {
        self.patch_point_id
    }

    pub fn instruction_offset(&self) -> usize {
        self.instruction_offset as usize
    }

    pub fn num_locations(&self) -> usize {
        self.num_locations as usize
    }

    pub fn locations(&self) -> LocationsIter<'input> {
        LocationsIter {
            data: self.locations,
            constants: self.constants,
            remaining_locations: self.num_locations as usize,
        }
    }

    pub fn num_live_outs(&self) -> usize {
        self.num_live_outs as usize
    }

    pub fn live_outs(&self) -> LiveOutsIter<'input> {
        LiveOutsIter {
            data: self.live_outs,
            remaining_live_outs: self.num_live_outs as usize,
        }
    }
}

pub struct LocationsIter<'input> {
    data: &'input [u8],
    constants: &'input [u64],
    remaining_locations: usize,
}

impl<'input> FallibleIterator for LocationsIter<'input> {
    type Item = Location;
    type Error = Error;

    fn next(&mut self) -> Result<'input, Option<Self::Item>> {
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

pub struct LiveOutsIter<'input> {
    data: &'input [u8],
    remaining_live_outs: usize,
}

impl<'input> FallibleIterator for LiveOutsIter<'input> {
    type Item = LiveOut;
    type Error = Error;

    fn next(&mut self) -> Result<'input, Option<Self::Item>> {
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
    Direct {
        register: DwarfRegNum,
        offset: isize,
    },
    Indirect {
        register: DwarfRegNum,
        offset: isize,
    },
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

    pub fn size(&self) -> usize {
        self.size as usize
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

    pub fn size(&self) -> usize {
        self.size as usize
    }
}

type Result<'a, T> = std::result::Result<T, Error>;

#[derive(Debug, Snafu)]
pub enum Error {
    ParserError {
        input: Vec<u8>,
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

    #[test]
    fn lifetimes_test() {
        let data: &[u8] = &[
            0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0xc0, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x02, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00, 0x00, 0xf6, 0xff, 0xff, 0xff, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let section = LLVMStackMaps::new(data);

        let stack_map;
        let function;
        let record;
        let location;
        {
            let stack_maps: Vec<_> = section.stack_maps().collect().unwrap();
            assert_eq!(stack_maps.len(), 1);
            stack_map = Some(stack_maps[0].clone());
            {
                let functions: Vec<_> = stack_maps[0].functions().collect().unwrap();
                assert_eq!(functions.len(), 1);
                function = Some(functions[0].clone());
                {
                    let records: Vec<_> = functions[0].records().collect().unwrap();
                    assert_eq!(records.len(), 1);
                    record = Some(records[0].clone());
                    {
                        let locations: Vec<_> = records[0].locations().collect().unwrap();
                        assert_eq!(locations.len(), 1);
                        location = Some(locations[0].clone());
                    }
                }
            }
        }

        let stack_map = stack_map.unwrap();
        assert_eq!(stack_map.version(), 3);

        let function = function.unwrap();
        assert_eq!(function.address(), 0x11c0);
        assert_eq!(function.stack_size(), 88);

        let record = record.unwrap();
        assert_eq!(record.patch_point_id(), 42);
        assert_eq!(record.instruction_offset(), 15);

        let location = location.unwrap();
        assert_eq!(
            *location.kind(),
            LocationKind::Direct {
                register: 6,
                offset: -10
            }
        );
        assert_eq!(location.size(), 8);
    }
}
