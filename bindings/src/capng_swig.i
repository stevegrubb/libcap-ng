/* capngswig.i --
 * Copyright 2009 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

%module capng
%{
        #include "./capng.h"
%}

#if defined(SWIGPYTHON)

%varargs(64, signed capability = -1) capng_updatev;

/*
 * SWIG supplies defaults only for omitted arguments. All 64 slots can be
 * supplied, so append a separate terminator to the generated C call.
 * Keep the macro scoped to that call.
 */
%exception capng_updatev %{
#define capng_updatev(...) capng_updatev(__VA_ARGS__, (unsigned int)-1)
	$action
#undef capng_updatev
%}

#endif

%define __signed__
signed
%enddef
#define __attribute(X) /*nothing*/
typedef unsigned __u32;
typedef unsigned uid_t;
#define __extension__ /*nothing*/
%include "./caps.h"

/*
 * The mutable string-returning APIs allocate their result for
 * CAPNG_PRINT_BUFFER. SWIG copies that result into a Python string, so release
 * the original C buffer after converting it.
 */
%typemap(ret) char *capng_print_caps_numeric {
	free($1);
}

%typemap(ret) char *capng_print_caps_text {
	free($1);
}

%include "./capng.h"

/* SWIG does not emit macros containing a C cast. */
#undef CAPNG_UNSET_ROOTID
%constant uid_t CAPNG_UNSET_ROOTID = (uid_t)-1;
