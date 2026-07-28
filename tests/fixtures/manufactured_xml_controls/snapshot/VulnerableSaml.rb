require "nokogiri"
require "rexml/document"

def authenticated_subject(raw_xml, certificate)
  nokogiri_document = Nokogiri::XML(raw_xml)
  rexml_document = REXML::Document.new(raw_xml)
  return unless verify_signature(nokogiri_document, certificate)

  REXML::XPath.first(rexml_document, "//Assertion/Subject/NameID").text
end
