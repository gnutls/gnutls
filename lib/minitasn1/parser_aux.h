/*
 * Copyright (C) 2000-2012 Free Software Foundation, Inc.
 *
 * This file is part of LIBTASN1.
 *
 * The LIBTASN1 library is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef _PARSER_AUX_H
#define _PARSER_AUX_H

#define DER_LEN 16

/***************************************/
/*  Functions used by ASN.1 parser     */
/***************************************/
ASN1_TYPE _asn1_add_static_node (unsigned int type);

ASN1_TYPE
_asn1_set_value (ASN1_TYPE node, const void *value, unsigned int len);

ASN1_TYPE _asn1_set_value_m (ASN1_TYPE node, void *value, unsigned int len);

ASN1_TYPE
_asn1_set_value_octet (ASN1_TYPE node, const void *value, unsigned int len);

ASN1_TYPE
_asn1_append_value (ASN1_TYPE node, const void *value, unsigned int len);

ASN1_TYPE _asn1_set_name (ASN1_TYPE node, const char *name);

ASN1_TYPE _asn1_cpy_name (ASN1_TYPE dst, ASN1_TYPE src);

ASN1_TYPE _asn1_set_right (ASN1_TYPE node, ASN1_TYPE right);

ASN1_TYPE _asn1_get_last_right (ASN1_TYPE node);

void _asn1_remove_node (ASN1_TYPE node);

void _asn1_delete_list (void);

void _asn1_delete_list_and_nodes (void);

char *_asn1_ltostr (long v, char *str);

ASN1_TYPE _asn1_find_up (ASN1_TYPE node);

asn1_retCode _asn1_change_integer_value (ASN1_TYPE node);

asn1_retCode _asn1_expand_object_id (ASN1_TYPE node);

asn1_retCode _asn1_type_set_config (ASN1_TYPE node);

asn1_retCode _asn1_check_identifier (ASN1_TYPE node);

asn1_retCode _asn1_set_default_tag (ASN1_TYPE node);

/******************************************************************/
/* Function : _asn1_get_right                                     */
/* Description: returns the element pointed by the RIGHT field of */
/*              a NODE_ASN element.                               */
/* Parameters:                                                    */
/*   node: NODE_ASN element pointer.                              */
/* Return: field RIGHT of NODE.                                   */
/******************************************************************/
inline static ASN1_TYPE
_asn1_get_right (ASN1_TYPE node)
{
  if (node == NULL)
    return NULL;
  return node->right;
}

/******************************************************************/
/* Function : _asn1_set_down                                      */
/* Description: sets the field DOWN in a NODE_ASN element.        */
/* Parameters:                                                    */
/*   node: element pointer.                                       */
/*   down: pointer to a NODE_ASN element that you want be pointed */
/*          by NODE.                                              */
/* Return: pointer to *NODE.                                      */
/******************************************************************/
inline static ASN1_TYPE
_asn1_set_down (ASN1_TYPE node, ASN1_TYPE down)
{
  if (node == NULL)
    return node;
  node->down = down;
  if (down)
    down->left = node;
  return node;
}

/******************************************************************/
/* Function : _asn1_get_down                                      */
/* Description: returns the element pointed by the DOWN field of  */
/*              a NODE_ASN element.                               */
/* Parameters:                                                    */
/*   node: NODE_ASN element pointer.                              */
/* Return: field DOWN of NODE.                                    */
/******************************************************************/
inline static ASN1_TYPE
_asn1_get_down (ASN1_TYPE node)
{
  if (node == NULL)
    return NULL;
  return node->down;
}

/******************************************************************/
/* Function : _asn1_get_name                                      */
/* Description: returns the name of a NODE_ASN element.           */
/* Parameters:                                                    */
/*   node: NODE_ASN element pointer.                              */
/* Return: a null terminated string.                              */
/******************************************************************/
inline static char *
_asn1_get_name (ASN1_TYPE node)
{
  if (node == NULL)
    return NULL;
  return node->name;
}

/******************************************************************/
/* Function : _asn1_mod_type                                      */
/* Description: change the field TYPE of an NODE_ASN element.     */
/*              The new value is the old one | (bitwise or) the   */
/*              paramener VALUE.                                  */
/* Parameters:                                                    */
/*   node: NODE_ASN element pointer.                              */
/*   value: the integer value that must be or-ed with the current */
/*          value of field TYPE.                                  */
/* Return: NODE pointer.                                          */
/******************************************************************/
inline static ASN1_TYPE
_asn1_mod_type (ASN1_TYPE node, unsigned int value)
{
  if (node == NULL)
    return node;
  node->type |= value;
  return node;
}

#endif
