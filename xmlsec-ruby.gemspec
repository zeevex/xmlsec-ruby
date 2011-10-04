spec = Gem::Specification.new do |s|
	s.name = 'xmlsec-ruby'
	s.version = '0.1.1'
	s.summary = 'Ruby bindings for xmlsec1'
	s.extensions = ['ext/xmlsec/extconf.rb']
	s.files = ["ext/xmlsec/simple-xmlsec.c", "lib/xmlsec.rb"]
	s.author = 'Victor Lin'
	s.email = 'victor@coupa.com'
	s.homepage = 'http://github.com/wonnage/xmlsec-ruby'
	s.description = <<-EOF
	xmlsec-ruby is a project using SWIG to create ruby bindings
	for the xmlsec library (http://www.aleksey.com/xmlsec/). 
	EOF
end
