/* -*- c -*- */
/*
 * This file is part of TC-PKCS11. 
 * (c) 1999 TC TrustCenter for Security in DataNetworks GmbH 
 *
 * TC-PKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *  
 * TC-PKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with TC-PKCS11; see the file COPYING.  If not, write to the Free
 * Software Foundation, 59 Temple Place - Suite 330, Boston, MA 02111, USA.  
 */
/*
 * RCSID:       $Id$
 * Source:      $Source$
 * Last Delta:  $Date$ $Revision$ $Author$
 * State:       $State$ $Locker$
 * NAME:        pkcs11_guile.h
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log$
 * HISTORY:     Revision 1.2  1999/07/20 17:39:59  lbe
 * HISTORY:     fix bug in gdbm Makefile: there is not allways an 'install' around
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:06  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/01/19 12:19:44  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/11/04 17:44:48  lbe
 * HISTORY:     debug-lockdown
 * HISTORY:
 */
 
#ifndef PKCS11_GUILE_H
#define PKCS11_GUILE_H

#include "cryptoki.h"

SCM ci_simple_test();
CK_ATTRIBUTE_PTR ci_list2template(SCM list, CK_ULONG CK_PTR count);
SCM ci_template2list(CK_ATTRIBUTE_PTR template, CK_ULONG ulCount);
void ci_template_delete(CK_ATTRIBUTE_PTR template, CK_ULONG ulCount);
SCM ci_parse_byte_stream(SCM byte_string);
SCM ci_unparse_string(SCM byte_string);
CK_MECHANISM_PTR ci_list2mechanism(SCM mechanism_list);
void ci_mechanism_delete(CK_MECHANISM_PTR);

SCM ck_initialize();
SCM ck_finalize();
SCM ck_get_info();
SCM ck_get_slot_list(SCM tokenp_bool);
SCM ck_get_token_info(SCM slot_int);
SCM ck_get_slot_info(SCM slot_int);
SCM ck_get_mechanism_list(SCM slot_ulong);
SCM ck_get_mechanism_info(SCM slot_ulong, SCM mech_type_ulong);
SCM ck_open_session(SCM slot_ulong, SCM flags);
SCM ck_close_session(SCM handle_ulong);
SCM ck_find_objects_init(SCM session_ulong, SCM attribs_list);
SCM ck_find_objects(SCM session_ulong);
SCM ck_find_objects_final(SCM session_ulong);
SCM ck_create_object(SCM session_ulong, SCM attribs_list);
SCM ck_destroy_object(SCM session_ulong, SCM object_ulong);
SCM ck_encrypt_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong);
SCM ck_encrypt(SCM session_ulong, SCM data_string, SCM null_data);
SCM ck_encrypt_update(SCM session_ulong, SCM data_string, SCM null_data);
SCM ck_encrypt_final(SCM session_ulong, SCM null_data);
SCM ck_decrypt_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong);
SCM ck_decrypt(SCM session_ulong, SCM data_string, SCM null_data);
SCM ck_decrypt_update(SCM session_ulong, SCM data_string, SCM null_data);
SCM ck_decrypt_final(SCM session_ulong, SCM null_data);
SCM ck_digest_init(SCM session_ulong, SCM mechansim_list);
SCM ck_digest(SCM session_ulong, SCM data_string, SCM null_data);
SCM ck_digest_update(SCM session_ulong, SCM data_string);
SCM ck_digest_key(SCM session_ulong, SCM key_ulong);
SCM ck_digest_final(SCM session_ulong, SCM null_data);
SCM ck_sign_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong);
SCM ck_sign(SCM session_ulong, SCM data_string, SCM null_data);
SCM ck_sign_update(SCM session_ulong, SCM data_string);
SCM ck_sign_final(SCM session_ulong, SCM null_data);
SCM ck_sign_recover_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong);
SCM ck_sign_recover(SCM session_ulong, SCM data_string, SCM null_data);
SCM ck_generate_key(SCM session_ulong, SCM mechanism_string, SCM template_string);
SCM ck_generate_key_pair(SCM session, SCM mechanism, SCM public_template, SCM private_template);
SCM ck_login(SCM session_ulong, SCM user_ulong, SCM pin_string);
SCM ck_logout(SCM session_ulong);
SCM ck_init_pin(SCM session_ulong, SCM pin_string);
SCM ck_set_pin(SCM session_ulong, SCM oldpin_string, SCM newpin_string);
SCM ck_close_all_sessions(SCM slot_ulong);
SCM ck_get_session_info(SCM session_ulong);
SCM ck_copy_object(SCM session_ulong, SCM object_ulong, SCM template_list);
SCM ck_verify_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong);
SCM ck_verify(SCM session_ulong, SCM data_string, SCM signature_string);
SCM ck_verify_update(SCM session_ulong, SCM part_string);
SCM ck_verify_final(SCM session_ulong, SCM signature_string);
SCM ck_verify_recover_init(SCM session_ulong, SCM mechanism_list, SCM key_ulong);
SCM ck_verify_recover(SCM session_ulong, SCM signature_string, SCM null_data);
SCM ck_init_token(SCM slot_ulong, SCM pin_string, SCM labe_string);
SCM ck_seed_random(SCM session_ulong, SCM seed_string);
SCM ck_generate_random(SCM session_ulong, SCM len_ulong);
SCM ck_get_object_size(SCM session_ulong, SCM object_ulong);
SCM ck_get_attribute_value(SCM session_ulong, SCM object_ulong, SCM template_list);
SCM ck_set_attribute_value(SCM session_ulong, SCM object_ulong, SCM template_list);
SCM ck_get_operation_state(SCM session_ulong, SCM null_data);
SCM ck_set_operation_state(SCM session, SCM state, SCM enc_key, SCM auth_key);
SCM ck_digest_encrypt_update(SCM session, SCM part, SCM null_data);
SCM ck_decrypt_digest_update(SCM session, SCM enc_part, SCM null_data);
SCM ck_sign_encrypt_update(SCM session, SCM part, SCM null_data);
SCM ck_decrypt_verify_update(SCM session, SCM enc_part, SCM null_data);
SCM ck_wrap_key(SCM session, SCM mech_list, SCM wrapper, SCM wrappee, SCM null_data);
SCM ck_unwrap_key(SCM session, SCM mechanism, SCM unwrapper, SCM wrapped, SCM template);
SCM ck_derive_key(SCM session, SCM mechanism, SCM base_key, SCM template);
SCM ck_get_function_status(SCM session);
SCM ck_cancel_function(SCM session);
SCM ck_wait_for_slot_event(SCM flags_ulong);

#ifndef NO_OPENSSL_CODE
SCM ch_create_cert_req(SCM session_ulong, SCM priv_key_ulong, SCM pub_key_ulong, SCM subject_list, SCM file_string);
#endif
#endif /* PKCS11_GUILE_H */
