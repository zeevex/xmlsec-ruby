%module xmlsec
%{ 
#include <libxml/tree.h>
%}

%typemap(in) xmlDocPtr {
xmlDocPtr doc;
Data_Get_Struct($input, xmlDocPtr, doc);
$1 = doc;
}

%include simple-xmlsec.h
