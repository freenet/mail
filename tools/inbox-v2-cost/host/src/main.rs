//! Runs the cost guest's calls under wasmtime and reports what each costs.
//!
//! host fuel <guest.wasm> <dir> <case>...
//!     Each call's fuel: wasm instructions executed, the same on any machine.
//! host time <guest.wasm> <dir> <case>...
//!     Each call's wall clock without fuel, best of three, as core runs a
//!     contract (cranelift, epoch interruption, no fuel).
//!
//! A case is `validate:<state>` or `update:<state>:<kind>:<a>[:<b>]`, kind
//! `delta`, `state` or `both`, the files under <dir>. Each case gets a fresh
//! instance, as each contract call does. One line per case:
//! `<case> ret=<n> fuel=<n>` or `<case> ret=<n> ms=<n>`.

use std::time::Instant;

use wasmtime::{Config, Engine, Instance, Module, Result, Store};

/// One contract call, inputs bound.
type Call = Box<dyn FnOnce(&mut Store<()>) -> Result<u32>>;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().expect("fuel or time");
    let fuel = match mode.as_str() {
        "fuel" => true,
        "time" => false,
        other => panic!("mode {other}: fuel or time"),
    };
    let path = args.next().expect("guest.wasm");
    let dir = args.next().expect("input dir");
    let cases: Vec<String> = args.collect();
    let read = |n: &str| std::fs::read(format!("{dir}/{n}")).unwrap();

    let mut cfg = Config::new();
    cfg.consume_fuel(fuel);
    cfg.epoch_interruption(!fuel);
    let engine = Engine::new(&cfg)?;
    let module = Module::from_file(&engine, &path)?;

    for case in cases {
        let f: Vec<&str> = case.split(':').collect();
        let runs = if fuel { 1 } else { 3 };
        let mut best = f64::MAX;
        let mut used = 0;
        let mut ret = 0;
        for _ in 0..runs {
            let mut store = Store::new(&engine, ());
            if fuel {
                store.set_fuel(u64::MAX)?;
            } else {
                store.set_epoch_deadline(u64::MAX / 2);
            }
            let inst = Instance::new(&mut store, &module, &[])?;
            let mem = inst.get_memory(&mut store, "memory").expect("memory");
            let alloc = inst.get_typed_func::<u32, u32>(&mut store, "alloc")?;
            let put = |store: &mut Store<()>, name: &str| -> Result<(u32, u32)> {
                let bytes = read(name);
                let p = alloc.call(&mut *store, bytes.len() as u32)?;
                mem.write(&mut *store, p as usize, &bytes)?;
                Ok((p, bytes.len() as u32))
            };
            let (pp, pl) = put(&mut store, "params.bin")?;
            let (sp, sl) = put(&mut store, f[1])?;
            // Every input is in memory before the clock and the fuel count start.
            let call: Call = if f[0] == "validate" {
                let validate =
                    inst.get_typed_func::<(u32, u32, u32, u32), u32>(&mut store, "validate")?;
                Box::new(move |store| validate.call(store, (pp, pl, sp, sl)))
            } else {
                let kind = match f[2] {
                    "delta" => 0,
                    "state" => 1,
                    "both" => 2,
                    other => panic!("kind {other}"),
                };
                let (ap, al) = put(&mut store, f[3])?;
                let (bp, bl) = match f.get(4) {
                    Some(name) => put(&mut store, name)?,
                    None => (0, 0),
                };
                let update = inst
                    .get_typed_func::<(u32, u32, u32, u32, u32, u32, u32, u32, u32), u32>(
                        &mut store, "update",
                    )?;
                Box::new(move |store| update.call(store, (pp, pl, sp, sl, kind, ap, al, bp, bl)))
            };
            let before = if fuel { store.get_fuel()? } else { 0 };
            let t = Instant::now();
            ret = call(&mut store)?;
            let elapsed = t.elapsed().as_secs_f64();
            if fuel {
                used = before - store.get_fuel()?;
            }
            best = best.min(elapsed);
        }
        if fuel {
            println!("{case} ret={ret} fuel={used}");
        } else {
            println!("{case} ret={ret} ms={:.0}", best * 1e3);
        }
    }
    Ok(())
}
