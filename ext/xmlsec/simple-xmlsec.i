%module xmlsec
%{ 
require 'ffi'

module Xmlsec
  ffi_lib [File.expand_path(File.join(File.dirname(__FILE__), 'xmlsec_ruby.bundle')), 'xmlsec_ruby']
  xmlDocPtr = :pointer
%}

%typemap(in) xmlDocPtr {
xmlDocPtr doc;
Data_Get_Struct($input, xmlDocPtr, doc);
$1 = doc;
}

%include simple-xmlsec.h

%{
end
%}
