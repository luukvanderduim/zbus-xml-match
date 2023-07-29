#![allow(unnameable_test_items)]

use std::{path::PathBuf, str::FromStr};
use zbus::{xml::Node, zvariant::Signature, Error::InterfaceNotFound, Error::MissingParameter};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Gets the signature of a signal's return type from XML.
///
/// Retrieval of signatures from the XML protocol definitions allows crates to verify if  
/// the signal's return type and the representing type in the Rust code are the same.
///
/// Verification might look like this:
///
/// # Examples
///
/// ```rust
/// use zbus::zvariant::Type;
/// use atspi::cache::CacheItem;
/// use zbus_xml_match::get_signature_of_signal_body_type;
///
/// let xml = std::path::PathBuf::from("xml/Cache.xml");
/// let interface_name = "org.a11y.atspi.Cache";
/// let member_name = "AddAccessible";
/// let kind = Some("nodeAdded");
///     
/// let signature = get_signature_of_signal_body_type(xml, interface_name, member_name, kind).unwrap();
/// assert_eq!(signature, CacheItem::signature());
/// ```
pub fn get_signature_of_signal_body_type<'a>(
    xml_path: PathBuf,
    interface_name: &'a str,
    member_name: &'a str,
    kind: Option<&'a str>,
) -> Result<Signature<'a>> {
    let xml = std::fs::read_to_string(xml_path)?;
    let node = Node::from_str(&xml)?;
    let interfaces = node.interfaces();
    let interface = interfaces
        .iter()
        .find(|iface| iface.name() == interface_name)
        .ok_or(InterfaceNotFound)?;

    let signals = interface.signals();
    let signal = signals
        .iter()
        .find(|signal| signal.name() == member_name)
        .ok_or(MissingParameter("no {member_name} found in {signals:?}"))?;

    let args = signal.args();
    let arg = args
        .iter()
        .find(|arg| arg.name() == kind)
        .ok_or(zbus::Error::MissingParameter("no {kind} found in {args:?}"))?;

    let signature = arg.ty().to_owned();

    // If the protocol definition does not provide a valid signature, then our problems are of different order.
    let signature = Signature::from_string_unchecked(signature);

    Ok(signature)
}

/// Gets the signature of a method's return type from XML.
///
/// Retrieval of signatures from the XML protocol definitions allows crates to verify if
/// the method's return type and the representing type in the Rust code are the same.
///     
/// Verification might look like this:
///     
/// # Examples
///     
/// ```rust
/// use zbus::zvariant::Type;
/// use atspi::Role;
/// use zbus_xml_match::get_signature_of_method_return_type_from_xml;
///     
/// let xml = std::path::PathBuf::from("xml/Accessible.xml");
/// let interface_name = "org.a11y.atspi.Accessible";
/// let member_name = "GetRole";
///     
/// let signature = get_signature_of_method_return_type_from_xml(xml, interface_name, member_name).unwrap();
/// assert_eq!(signature, Role::signature());
/// ```
pub fn get_signature_of_method_return_type_from_xml<'a>(
    xml_path: PathBuf,
    interface_name: &str,
    member_name: &str,
) -> Result<Signature<'a>> {
    let xml = std::fs::read_to_string(xml_path)?;
    let node = Node::from_str(&xml)?;
    let interfaces = node.interfaces();
    let interface = interfaces
        .iter()
        .find(|iface| iface.name() == interface_name)
        .ok_or(InterfaceNotFound)?;

    let methods = interface.methods();
    let method = methods
        .iter()
        .find(|method| method.name() == member_name)
        .ok_or(MissingParameter("no {member_name} found in {methods:?}"))?;

    let args = method.args();
    let arg = args
        .iter()
        .find(|arg| arg.direction() == Some("out"))
        .ok_or(MissingParameter(
            "no argument with 'out' direction in {args:?}",
        ))?;

    let signature = arg.ty().to_owned();

    // If the protocol definition does not provide a valid signature, then our problems are of different order.
    let signature = Signature::from_string_unchecked(signature);

    Ok(signature)
}

/// Constructs the signature of an AT-SPI2 event from the signal's arguments in XML.
///
/// Retrieval of signatures from the XML protocol definitions allows crates to verify if
/// the signal's body type and the representing type in the Rust code are the same.
///
/// Verification might look like this:
///
/// # Examples
///
/// ```rust
/// use zbus::zvariant::Type;
/// use atspi::events::EventBodyOwned;
/// use zbus_xml_match::get_signature_of_atspi_event_from_xml;
///
/// let xml = std::path::PathBuf::from("xml/Event.xml");
/// let interface_name = "org.a11y.atspi.Event.Object";
/// let member_name = "StateChanged";
///
/// let signature = get_signature_of_atspi_event_from_xml(xml, interface_name, member_name).unwrap();
/// assert_eq!(signature, EventBodyOwned::signature());
/// ```
pub fn get_signature_of_atspi_event_from_xml<'a>(
    xml_path: PathBuf,
    interface_name: &'a str,
    member_name: &'a str,
) -> Result<Signature<'a>> {
    let xml = std::fs::read_to_string(xml_path)?;
    let node = Node::from_str(&xml)?;
    let interfaces = node.interfaces();
    let interface = interfaces
        .iter()
        .find(|iface| iface.name() == interface_name)
        .ok_or(InterfaceNotFound)?;

    let signals = interface.signals();
    let method = signals
        .iter()
        .find(|signal| signal.name() == member_name)
        .ok_or(MissingParameter("no {member_name} found in {signals:?}"))?;

    let args = method.args();
    let mut signature = args.into_iter().map(|arg| arg.ty()).collect::<String>();

    // Demarshall the signature into a rust struct signature.
    signature.insert(0, '(');
    signature.push(')');

    // If the protocol definition does not provide a valid signature, then our problems are of different order.
    let signature = Signature::from_string_unchecked(signature);

    Ok(signature)
}

/// Expands to a test function that checks if the signature of an AT-SPI2 event signal's aggregated argument types match
/// the signature of the corresponding type in the Rust code `EventBodyOwned`.
///
/// # Examples
///
/// ```rust
/// use zbus::zvariant::Type;
/// use atspi::events::EventBodyOwned;
/// use zbus_xml_match::test_atspi_event_signature_and_type_match;
///
/// test_atspi_event_signature_and_type_match!(EventBodyOwned, "xml/Event.xml", "org.a11y.atspi.Event.Object", "StateChanged", test_get_atspi_event_signature_and_type_match_object_state_changed);     
/// ```
#[macro_export]
macro_rules! test_atspi_event_signature_and_type_match {
    ($type:ty, $file_name:literal, $interface_name:literal, $signal_name:literal, $test_fn_name:tt) => {
        #[test]
        #[allow(dead_code)]
        fn $test_fn_name() {
            let xml = PathBuf::from($file_name);
            let interface_name = $interface_name;
            let member_name = $signal_name;

            let signature =
                get_signature_of_atspi_event_from_xml(xml, interface_name, member_name).unwrap();

            assert_eq!(<$type as Type>::signature(), signature);
        }
    };
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::get_signature_of_atspi_event_from_xml;
    use crate::get_signature_of_signal_body_type;
    use crate::test_atspi_event_signature_and_type_match;

    use atspi::Role;
    use atspi::{
        cache::CacheItem,
        events::{Accessible, EventBodyOwned},
    };
    use zbus::zvariant::Type;

    #[test]
    fn test_get_signature_of_cache_add_accessible() {
        let xml = PathBuf::from("xml/Cache.xml");
        let interface_name = "org.a11y.atspi.Cache";
        let member_name = "AddAccessible";
        let kind = Some("nodeAdded");

        let signature =
            get_signature_of_signal_body_type(xml, interface_name, member_name, kind).unwrap();
        assert_eq!(signature, CacheItem::signature());
    }

    #[test]
    fn test_get_signature_of_role_get_role() {
        let xml = PathBuf::from("xml/Accessible.xml");
        let interface_name = "org.a11y.atspi.Accessible";
        let member_name = "GetRole";

        let signature =
            get_signature_of_method_return_type_from_xml(xml, interface_name, member_name).unwrap();
        assert_eq!(signature, Role::signature());
    }

    #[test]
    fn test_get_signature_of_cache_remove_accessible() {
        let xml = PathBuf::from("xml/Cache.xml");
        let interface_name = "org.a11y.atspi.Cache";
        let member_name = "RemoveAccessible";
        let kind = Some("nodeRemoved");

        let signature =
            get_signature_of_signal_body_type(xml, interface_name, member_name, kind).unwrap();
        assert_eq!(signature, Accessible::signature());
    }

    #[test]
    fn test_get_atspi_mouse_event_signature() {
        let xml = PathBuf::from("xml/Event.xml");
        let interface_name = "org.a11y.atspi.Event.Mouse";
        let member_name = "Abs";

        let signature =
            get_signature_of_atspi_event_from_xml(xml, interface_name, member_name).unwrap();
        assert_eq!(signature, EventBodyOwned::signature());
    }

    #[test]
    fn test_get_atspi_object_event_signature() {
        use atspi::events::EventBodyOwned;
        use zbus::zvariant::Type;

        test_atspi_event_signature_and_type_match!(
            EventBodyOwned,
            "xml/Event.xml",
            "org.a11y.atspi.Event.Text",
            "TextCaretMoved",
            test_get_atspi_event_signature_and_type_match_text_caret_moved
        );
    }
}
