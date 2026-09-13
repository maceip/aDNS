#![no_main]
#![forbid(unsafe_code)]
use adns_wire::{Message,PacketReader,WireName};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data:&[u8]|{
    if data.len()>65535{return;}
    for mut offset in [0,data.len()/2,data.len().saturating_sub(1)]{let _=WireName::parse_wire(data,&mut offset);}
    let mut reader=PacketReader::new(data);if let Ok(view)=reader.record_view(){let borrowed=view.typed();let owned=view.to_owned();assert_eq!(borrowed.is_ok(),owned.is_ok());}
    if let Ok(message)=Message::parse(data){let serialized=match message.to_wire(){Ok(bytes)=>bytes,Err(adns_wire::DnsError::PacketTooLong)=>return,Err(e)=>panic!("parsed message cannot be serialized: {e}")};let reparsed=Message::parse(&serialized).expect("writer emits valid wire message");assert_eq!(message,reparsed);}
});
