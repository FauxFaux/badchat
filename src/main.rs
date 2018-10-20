#[macro_use]
extern crate failure;
extern crate mio;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate rustls;
extern crate vecio;

mod serv;

use failure::Error;
use failure::ResultExt;

fn main() -> Result<(), Error> {
    env_logger::Builder::new().parse("trace").init();

    serv::serve_forever()
}
