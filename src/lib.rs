macro_rules! test_signature_match {
	($type:ty, $file_name:literal, $interface_name:literal, $method_name:literal) => {
		#[test]
		fn test_matching_signature() -> Result<(), Box<dyn std::error::Error>> {
			use std::str::FromStr;
			use std::io::Read;
			use std::fs::File;
			use zbus::xml::Node;

			let mut file = File::open($file_name)?;
			let mut contents = String::new();
			file.read_to_string(&mut contents)?;
			println!("{:?}", contents);
			let node = Node::from_str(&contents)?;
			Ok(())
		}
	}
}
struct X;

test_signature_match!(X, "xml/Event.xml", "org.a11y.atspi.Event.Object", "TextChanged");
