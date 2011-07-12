/* simple-xmlsec.h
 *
 * Sudish Joseph <sudish@gmail.com>, 2011-07-11
 */

#ifndef SIMPLE_XMLSEC_H_INCLUDED
#define SIMPLE_XMLSEC_H_INCLUDED 1

#ifdef __cplusplus
extern "C" {
#endif

extern int verify_document(xmlDocPtr doc, const char* key);
extern int verify_file(const char* xmlMessage, const char* key);
extern int sign_file(const char* xmlMessage, const char* key);
extern int sign_document(xmlDocPtr doc, const char* key);

#ifdef __cplusplus
}
#endif /* extern "C" */

#endif /* SIMPLE_XMLSEC_H_INCLUDED */
