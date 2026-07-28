require "nokogiri"

def authenticated_subject(raw_xml, certificate)
  document = Nokogiri::XML(raw_xml) { |config| config.strict.nonet }
  verified_assertion = verify_and_return_signed_node(document, certificate)
  return unless verified_assertion

  verified_assertion.at_xpath("./Subject/NameID").text
end
