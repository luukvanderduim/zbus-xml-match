# `zbus-xml-match`

A way to match the signature of `<T as zbus::Type>::signature()` with a matching DBus XML file, interface and member.
This is to ensure that a struct's implementation of `signature()` matches the an external XML file.
The reason for this is that since DBus' XML is, in theory, meant to be the "source of all truth", it is dangerous to have `struct`s that can deviate from the XML at any time---especially since other applications might assume conformance with the XML.

