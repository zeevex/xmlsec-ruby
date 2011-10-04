 
require 'ffi'

module Xmlsec
  extend FFI::Library
  ffi_lib [File.expand_path(File.join(File.dirname(__FILE__), 'xmlsec_ruby.bundle')), 'xmlsec_ruby']
  xmlDocPtr = :pointer
  attach_function :verify_document, [ xmlDocPtr, :string ], :int
  attach_function :verify_file, [ :string, :string ], :int
  attach_function :sign_file, [ :string, :string ], :int
  attach_function :sign_document, [ xmlDocPtr, :string ], :int

end
