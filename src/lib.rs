use std::collections::HashMap;
use zbus::zvariant::{Value, Type, Signature};

macro_rules! test_signature_match {
	($type:ty, $file_name:literal, $interface_name:literal, $signal_name:literal) => {
		#[test]
		fn test_matching_signature() -> Result<(), Box<dyn std::error::Error>> {
			use std::str::FromStr;
			use std::io::Read;
			use std::fs::File;
			use zbus::xml::Node;

			let mut file = File::open($file_name)?;
			let mut contents = String::new();
			file.read_to_string(&mut contents)?;
			let node = Node::from_str(&contents)?;
			let interfaces = node.interfaces();
			let interface = interfaces
				.iter()
				.find(|iface| iface.name() == $interface_name)
				.expect(&format!("Could not find interface {}; options: {:?}", $interface_name, interfaces));
			let signals = interface.signals();
			let method = signals
				.iter()
				.find(|signal| signal.name() == $signal_name)
				.expect(&format!("Could not find method {}; options: {:?}", $signal_name, signals));
			let args = method.args();
			let mut signature_parts = args
				.into_iter()
				.filter_map(|arg| if arg.name().is_some() {
					Some(arg.ty().to_string())
				} else {
					None
				})
				.collect::<Vec<String>>();
			signature_parts.push(")".to_string());
			signature_parts.insert(0, "(".to_string());
			let signature = signature_parts.join("");
			assert_eq!(<$type as Type>::signature().as_str(), signature);
			Ok(())
		}
	}
}

#[derive(Type)]
struct X<'a> { 
	a: String,
	i: i32,
	i2: i32,
	v: Value<'a>,
	h: HashMap<String, Value<'a>>,
}

test_signature_match!(X, "xml/Event.xml", "org.a11y.atspi.Event.Object", "TextChanged");
