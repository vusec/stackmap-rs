use anyhow::Context;
use fallible_iterator::FallibleIterator;
use memmap2::Mmap;
use object::{Object, ObjectSection};
use stackmap::{Function, LLVMStackMaps, Location, Record, StackMap};
use std::{
    fs,
    path::{Path, PathBuf},
};
use structopt::StructOpt;

const STACK_MAPS_SECTION_NAME: &str = ".llvm_stackmaps";
#[derive(Debug, StructOpt)]
#[structopt(about = "A cmdline parser for LLVM StackMaps.")]
struct Opt {
    #[structopt(help = "Path to the ELF object to parse")]
    binary_path: PathBuf,
}

impl Opt {
    fn binary_path(&self) -> &Path {
        &self.binary_path
    }
}

fn print_location(location: &Location) {
    match location.kind() {
        stackmap::LocationKind::Register(register) => {
            print!("Register R#{}, ", register);
        }
        stackmap::LocationKind::Direct { register, offset } => {
            print!("Direct R#{} + {}, ", register, offset);
        }
        stackmap::LocationKind::Indirect { register, offset } => {
            print!("Indirect [R#{} + {}], ", register, offset);
        }
        stackmap::LocationKind::Constant(constant) => {
            print!("Constant {}, ", constant);
        }
    }
    println!("size: {}", location.size());
}

fn print_record(record: &Record) -> anyhow::Result<()> {
    println!(
        "    ID: {:#x}, instruction offset: {:#x}",
        record.patch_point_id(),
        record.instruction_offset()
    );

    println!("    {} locations:", record.num_locations());
    let mut locations_iter = record.locations().enumerate();
    while let Some((location_idx, location)) = locations_iter.next()? {
        print!("      #{}: ", location_idx);
        print_location(&location);
    }

    print!("    {} live-outs: [ ", record.num_live_outs());
    let mut live_outs_iter = record.live_outs();
    while let Some(live_out) = live_outs_iter.next()? {
        print!("{} ({}-bytes)", live_out.dwarf_reg_num(), live_out.size());
    }
    println!("]");

    Ok(())
}

fn print_function(function: &Function) -> anyhow::Result<()> {
    println!(
        "  address: {:#x}, stack size: {}",
        function.address(),
        function.stack_size(),
    );
    println!("  {} records:", function.num_records());

    let mut records_iter = function.records();
    while let Some(record) = records_iter.next()? {
        print_record(&record)?;
    }

    Ok(())
}

fn print_stack_map(stack_map: &StackMap) -> anyhow::Result<()> {
    println!("version: {}", stack_map.version(),);
    println!("{} functions:", stack_map.num_functions());

    let mut functions_iter = stack_map.functions();
    while let Some(function) = functions_iter.next()? {
        print_function(&function)?;
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::from_args();
    let binary_path = opt.binary_path();

    let binary_file = fs::File::open(&binary_path).context("Could not open binary file")?;
    let file_map = unsafe { Mmap::map(&binary_file).context("Could not map binary file")? };
    let object = object::File::parse(&file_map).context("Could not parse input file as object")?;

    let stack_maps_section = object
        .section_by_name(STACK_MAPS_SECTION_NAME)
        .with_context(|| {
            format!(
                "Could not find {} section in object",
                STACK_MAPS_SECTION_NAME
            )
        })?;
    let stack_maps_section_data = stack_maps_section
        .data()
        .with_context(|| format!("Could not get data for {} section", STACK_MAPS_SECTION_NAME))?;

    let llvm_stack_maps = LLVMStackMaps::new(stack_maps_section_data);

    let mut stack_maps_iter = llvm_stack_maps.stack_maps().enumerate();
    while let Some((stack_map_idx, stack_map)) = stack_maps_iter.next()? {
        print!("Stack map #{}: ", stack_map_idx);
        print_stack_map(&stack_map)?;
        println!();
    }

    Ok(())
}
