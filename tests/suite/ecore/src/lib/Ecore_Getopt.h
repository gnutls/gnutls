#ifndef _ECORE_GETOPT_H
#define _ECORE_GETOPT_H

#include <stdio.h>
#include <Eina.h>

#ifdef EAPI
#undef EAPI
#endif

#ifdef _WIN32
#ifdef EFL_ECORE_BUILD
#ifdef DLL_EXPORT
#define EAPI __declspec(dllexport)
#else
#define EAPI
#endif				/* ! DLL_EXPORT */
#else
#define EAPI __declspec(dllimport)
#endif				/* ! EFL_ECORE_BUILD */
#else
#ifdef __GNUC__
#if __GNUC__ >= 4
#define EAPI __attribute__ ((visibility("default")))
#else
#define EAPI
#endif
#else
#define EAPI
#endif
#endif				/* ! _WIN32 */

/**
 * @file Ecore_Getopt.h
 * @brief Contains powerful getopt replacement.
 *
 * This replacement handles both short (-X) or long options (--ABC)
 * options, with various actions supported, like storing one value and
 * already converting to required type, counting number of
 * occurrences, setting true or false values, show help, license,
 * copyright and even support user-defined callbacks.
 *
 * It is provided a set of C Pre Processor macros so definition is
 * straightforward.
 *
 * Values will be stored elsewhere indicated by an array of pointers
 * to values, it is given in separate to parser description so you can
 * use multiple values with the same parser.
 */


#ifdef __cplusplus
extern "C" {
#endif

	typedef enum {
		ECORE_GETOPT_ACTION_STORE,
		ECORE_GETOPT_ACTION_STORE_CONST,
		ECORE_GETOPT_ACTION_STORE_TRUE,
		ECORE_GETOPT_ACTION_STORE_FALSE,
		ECORE_GETOPT_ACTION_CHOICE,
		ECORE_GETOPT_ACTION_APPEND,
		ECORE_GETOPT_ACTION_COUNT,
		ECORE_GETOPT_ACTION_CALLBACK,
		ECORE_GETOPT_ACTION_HELP,
		ECORE_GETOPT_ACTION_VERSION,
		ECORE_GETOPT_ACTION_COPYRIGHT,
		ECORE_GETOPT_ACTION_LICENSE
	} Ecore_Getopt_Action;

	typedef enum {
		ECORE_GETOPT_TYPE_STR,
		ECORE_GETOPT_TYPE_BOOL,
		ECORE_GETOPT_TYPE_SHORT,
		ECORE_GETOPT_TYPE_INT,
		ECORE_GETOPT_TYPE_LONG,
		ECORE_GETOPT_TYPE_USHORT,
		ECORE_GETOPT_TYPE_UINT,
		ECORE_GETOPT_TYPE_ULONG,
		ECORE_GETOPT_TYPE_DOUBLE
	} Ecore_Getopt_Type;

	typedef enum {
		ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO = 0,
		ECORE_GETOPT_DESC_ARG_REQUIREMENT_YES = 1,
		ECORE_GETOPT_DESC_ARG_REQUIREMENT_OPTIONAL = 3
	} Ecore_Getopt_Desc_Arg_Requirement;

	typedef union _Ecore_Getopt_Value Ecore_Getopt_Value;

	typedef struct _Ecore_Getopt_Desc_Store Ecore_Getopt_Desc_Store;
	typedef struct _Ecore_Getopt_Desc_Callback
	    Ecore_Getopt_Desc_Callback;
	typedef struct _Ecore_Getopt_Desc Ecore_Getopt_Desc;
	typedef struct _Ecore_Getopt Ecore_Getopt;

	union _Ecore_Getopt_Value {
		char **strp;
		unsigned char *boolp;
		short *shortp;
		int *intp;
		long *longp;
		unsigned short *ushortp;
		unsigned int *uintp;
		unsigned long *ulongp;
		double *doublep;
		Eina_List **listp;
		void **ptrp;
	};

	struct _Ecore_Getopt_Desc_Store {
		Ecore_Getopt_Type type;/**< type of data being handled */
		Ecore_Getopt_Desc_Arg_Requirement arg_req;
		union {
			const char *strv;
			unsigned char boolv;
			short shortv;
			int intv;
			long longv;
			unsigned short ushortv;
			unsigned int uintv;
			unsigned long ulongv;
			double doublev;
		} def;
	};

	struct _Ecore_Getopt_Desc_Callback {
		unsigned char (*func) (const Ecore_Getopt * parser,
				       const Ecore_Getopt_Desc * desc,
				       const char *str, void *data,
				       Ecore_Getopt_Value * storage);
		const void *data;
		Ecore_Getopt_Desc_Arg_Requirement arg_req;
		const char *def;
	};

	struct _Ecore_Getopt_Desc {
		char shortname;
			   /**< used with a single dash */
		const char *longname;
			   /**< used with double dashes */
		const char *help;
			   /**< used by --help/ecore_getopt_help() */
		const char *metavar;
			   /**< used by ecore_getopt_help() with nargs > 0 */

		Ecore_Getopt_Action action;
				 /**< define how to handle it */
		union {
			const Ecore_Getopt_Desc_Store store;
			const void *store_const;
			const char *const *choices;	/* NULL terminated. */
			const Ecore_Getopt_Type append_type;
			const Ecore_Getopt_Desc_Callback callback;
			const void *dummy;
		} action_param;
	};

	struct _Ecore_Getopt {
		const char *prog;
		       /**< to be used when ecore_app_args_get() fails */
		const char *usage;
			/**< usage example, %prog is replaced */
		const char *version;
			  /**< if exists, --version will work */
		const char *copyright;
			    /**< if exists, --copyright will work */
		const char *license;
			  /**< if exists, --license will work */
		const char *description;
			      /**< long description, possible multiline */
		unsigned char strict:1;
			       /**< fail on errors */
		const Ecore_Getopt_Desc descs[];	/* NULL terminated. */
	};

#define ECORE_GETOPT_STORE_FULL(shortname, longname, help, metavar, type, arg_requirement, default_value) \
  {shortname, longname, help, metavar, ECORE_GETOPT_ACTION_STORE,        \
       {.store = {type, arg_requirement, default_value}}}

#define ECORE_GETOPT_STORE(shortname, longname, help, type)             \
  ECORE_GETOPT_STORE_FULL(shortname, longname, help, NULL, type,        \
                          ECORE_GETOPT_DESC_ARG_REQUIREMENT_YES, {})

#define ECORE_GETOPT_STORE_STR(shortname, longname, help)               \
  ECORE_GETOPT_STORE(shortname, longname, help, ECORE_GETOPT_TYPE_STR)
#define ECORE_GETOPT_STORE_BOOL(shortname, longname, help)              \
  ECORE_GETOPT_STORE(shortname, longname, help, ECORE_GETOPT_TYPE_BOOL)
#define ECORE_GETOPT_STORE_SHORT(shortname, longname, help)             \
  ECORE_GETOPT_STORE(shortname, longname, help, ECORE_GETOPT_TYPE_SHORT)
#define ECORE_GETOPT_STORE_INT(shortname, longname, help)               \
  ECORE_GETOPT_STORE(shortname, longname, help, ECORE_GETOPT_TYPE_INT)
#define ECORE_GETOPT_STORE_LONG(shortname, longname, help)              \
  ECORE_GETOPT_STORE(shortname, longname, help, ECORE_GETOPT_TYPE_LONG)
#define ECORE_GETOPT_STORE_USHORT(shortname, longname, help)            \
  ECORE_GETOPT_STORE(shortname, longname, help, ECORE_GETOPT_TYPE_USHORT)
#define ECORE_GETOPT_STORE_UINT(shortname, longname, help)              \
  ECORE_GETOPT_STORE(shortname, longname, help, ECORE_GETOPT_TYPE_UINT)
#define ECORE_GETOPT_STORE_ULONG(shortname, longname, help)             \
  ECORE_GETOPT_STORE(shortname, longname, help, ECORE_GETOPT_TYPE_ULONG)
#define ECORE_GETOPT_STORE_DOUBLE(shortname, longname, help)            \
  ECORE_GETOPT_STORE(shortname, longname, help, ECORE_GETOPT_TYPE_DOUBLE)


#define ECORE_GETOPT_STORE_METAVAR(shortname, longname, help, metavar, type) \
  ECORE_GETOPT_STORE_FULL(shortname, longname, help, metavar, type,        \
                          ECORE_GETOPT_DESC_ARG_REQUIREMENT_YES, {})

#define ECORE_GETOPT_STORE_METAVAR_STR(shortname, longname, help, metavar) \
  ECORE_GETOPT_STORE_METAVAR(shortname, longname, help, metavar, ECORE_GETOPT_TYPE_STR)
#define ECORE_GETOPT_STORE_METAVAR_BOOL(shortname, longname, help, metavar) \
  ECORE_GETOPT_STORE_METAVAR(shortname, longname, help, metavar, ECORE_GETOPT_TYPE_BOOL)
#define ECORE_GETOPT_STORE_METAVAR_SHORT(shortname, longname, help, metavar) \
  ECORE_GETOPT_STORE_METAVAR(shortname, longname, help, metavar, ECORE_GETOPT_TYPE_SHORT)
#define ECORE_GETOPT_STORE_METAVAR_INT(shortname, longname, help, metavar) \
  ECORE_GETOPT_STORE_METAVAR(shortname, longname, help, metavar, ECORE_GETOPT_TYPE_INT)
#define ECORE_GETOPT_STORE_METAVAR_LONG(shortname, longname, help, metavar) \
  ECORE_GETOPT_STORE_METAVAR(shortname, longname, help, metavar, ECORE_GETOPT_TYPE_LONG)
#define ECORE_GETOPT_STORE_METAVAR_USHORT(shortname, longname, help, metavar) \
  ECORE_GETOPT_STORE_METAVAR(shortname, longname, help, metavar, ECORE_GETOPT_TYPE_USHORT)
#define ECORE_GETOPT_STORE_METAVAR_UINT(shortname, longname, help, metavar) \
  ECORE_GETOPT_STORE_METAVAR(shortname, longname, help, metavar, ECORE_GETOPT_TYPE_UINT)
#define ECORE_GETOPT_STORE_METAVAR_ULONG(shortname, longname, help, metavar) \
  ECORE_GETOPT_STORE_METAVAR(shortname, longname, help, metavar, ECORE_GETOPT_TYPE_ULONG)
#define ECORE_GETOPT_STORE_METAVAR_DOUBLE(shortname, longname, help, metavar) \
  ECORE_GETOPT_STORE_METAVAR(shortname, longname, help, metavar, ECORE_GETOPT_TYPE_DOUBLE)


#define ECORE_GETOPT_STORE_DEF(shortname, longname, help, type, default_value) \
  ECORE_GETOPT_STORE_FULL(shortname, longname, help, NULL, type,               \
                          ECORE_GETOPT_DESC_ARG_REQUIREMENT_OPTIONAL,          \
                          default_value)

#define ECORE_GETOPT_STORE_DEF_STR(shortname, longname, help, default_value) \
  ECORE_GETOPT_STORE_DEF(shortname, longname, help,                          \
                         ECORE_GETOPT_TYPE_STR,                              \
                         {.strv = default_value})
#define ECORE_GETOPT_STORE_DEF_BOOL(shortname, longname, help, default_value) \
  ECORE_GETOPT_STORE_DEF(shortname, longname, help,                           \
                         ECORE_GETOPT_TYPE_BOOL,                              \
                         {.boolv = default_value})
#define ECORE_GETOPT_STORE_DEF_SHORT(shortname, longname, help, default_value) \
  ECORE_GETOPT_STORE_DEF(shortname, longname, help,                            \
                         ECORE_GETOPT_TYPE_SHORT,                              \
                         {.shortv = default_value})
#define ECORE_GETOPT_STORE_DEF_INT(shortname, longname, help, default_value) \
  ECORE_GETOPT_STORE_DEF(shortname, longname, help,                          \
                         ECORE_GETOPT_TYPE_INT,                              \
                         {.intv = default_value})
#define ECORE_GETOPT_STORE_DEF_LONG(shortname, longname, help, default_value) \
  ECORE_GETOPT_STORE_DEF(shortname, longname, help,                           \
                         ECORE_GETOPT_TYPE_LONG,                              \
                         {.longv = default_value})
#define ECORE_GETOPT_STORE_DEF_USHORT(shortname, longname, help, default_value) \
  ECORE_GETOPT_STORE_DEF(shortname, longname, help,                             \
                         ECORE_GETOPT_TYPE_USHORT,                              \
                         {.ushortv = default_value})
#define ECORE_GETOPT_STORE_DEF_UINT(shortname, longname, help, default_value) \
  ECORE_GETOPT_STORE_DEF(shortname, longname, help,                           \
                         ECORE_GETOPT_TYPE_UINT,                              \
                         {.uintv = default_value})
#define ECORE_GETOPT_STORE_DEF_ULONG(shortname, longname, help, default_value) \
  ECORE_GETOPT_STORE_DEF(shortname, longname, help,                            \
                         ECORE_GETOPT_TYPE_ULONG,                              \
                         {.ulongv = default_value})
#define ECORE_GETOPT_STORE_DEF_DOUBLE(shortname, longname, help, default_value) \
  ECORE_GETOPT_STORE_DEF(shortname, longname, help,                             \
                         ECORE_GETOPT_TYPE_DOUBLE,                              \
                         {.doublev = default_value})

#define ECORE_GETOPT_STORE_FULL_STR(shortname, longname, help, metavar, arg_requirement, default_value) \
  ECORE_GETOPT_STORE_FULL(shortname, longname, help, metavar,                                           \
                          ECORE_GETOPT_TYPE_STR,                                                        \
                          arg_requirement,                                                               \
                          {.strv = default_value})
#define ECORE_GETOPT_STORE_FULL_BOOL(shortname, longname, help, metavar, arg_requirement, default_value) \
  ECORE_GETOPT_STORE_FULL(shortname, longname, help, metavar,                                            \
                          ECORE_GETOPT_TYPE_BOOL,                                                        \
                          arg_requirement,                                                               \
                          {.boolv = default_value})
#define ECORE_GETOPT_STORE_FULL_SHORT(shortname, longname, help, metavar, arg_requirement, default_value) \
  ECORE_GETOPT_STORE_FULL(shortname, longname, help, metavar,                                             \
                          ECORE_GETOPT_TYPE_SHORT,                                                        \
                          arg_requirement,                                                                \
                          {.shortv = default_value})
#define ECORE_GETOPT_STORE_FULL_INT(shortname, longname, help, metavar, arg_requirement, default_value) \
  ECORE_GETOPT_STORE_FULL(shortname, longname, help, metavar,                                           \
                          ECORE_GETOPT_TYPE_INT,                                                        \
                          arg_requirement,                                                              \
                          {.intv = default_value})
#define ECORE_GETOPT_STORE_FULL_LONG(shortname, longname, help, metavar, arg_requirement, default_value) \
  ECORE_GETOPT_STORE_FULL(shortname, longname, help, metavar,                                            \
                          ECORE_GETOPT_TYPE_LONG,                                                        \
                          arg_requirement,                                                               \
                          {.longv = default_value})
#define ECORE_GETOPT_STORE_FULL_USHORT(shortname, longname, help, metavar, arg_requirement, default_value) \
  ECORE_GETOPT_STORE_FULL(shortname, longname, help, metavar,                                              \
                          ECORE_GETOPT_TYPE_USHORT,                                                        \
                          arg_requirement,                                                                 \
                          {.ushortv = default_value})
#define ECORE_GETOPT_STORE_FULL_UINT(shortname, longname, help, metavar, arg_requirement, default_value) \
  ECORE_GETOPT_STORE_FULL(shortname, longname, help, metavar,                                            \
                          ECORE_GETOPT_TYPE_UINT,                                                        \
                          arg_requirement,                                                               \
                          {.uintv = default_value})
#define ECORE_GETOPT_STORE_FULL_ULONG(shortname, longname, help, metavar, arg_requirement, default_value) \
  ECORE_GETOPT_STORE_FULL(shortname, longname, help, metavar,                                             \
                          ECORE_GETOPT_TYPE_ULONG,                                                        \
                          arg_requirement,                                                                \
                          {.ulongv = default_value})
#define ECORE_GETOPT_STORE_FULL_DOUBLE(shortname, longname, help, metavar, arg_requirement, default_value) \
  ECORE_GETOPT_STORE_FULL(shortname, longname, help, metavar,                                              \
                          ECORE_GETOPT_TYPE_DOUBLE,                                                        \
                          arg_requirement,                                                                 \
                          {.doublev = default_value})

#define ECORE_GETOPT_STORE_CONST(shortname, longname, help, value)   \
  {shortname, longname, help, NULL, ECORE_GETOPT_ACTION_STORE_CONST, \
       {.store_const = value}}
#define ECORE_GETOPT_STORE_TRUE(shortname, longname, help)          \
  {shortname, longname, help, NULL, ECORE_GETOPT_ACTION_STORE_TRUE, \
       {.dummy = NULL}}
#define ECORE_GETOPT_STORE_FALSE(shortname, longname, help)          \
  {shortname, longname, help, NULL, ECORE_GETOPT_ACTION_STORE_FALSE, \
       {.dummy = NULL}}

#define ECORE_GETOPT_CHOICE(shortname, longname, help, choices_array) \
  {shortname, longname, help, NULL, ECORE_GETOPT_ACTION_CHOICE,       \
       {.choices = choices_array}}
#define ECORE_GETOPT_CHOICE_METAVAR(shortname, longname, help, metavar, choices_array) \
  {shortname, longname, help, metavar, ECORE_GETOPT_ACTION_CHOICE,                     \
       {.choices = choices_array}}


#define ECORE_GETOPT_APPEND(shortname, longname, help, sub_type) \
  {shortname, longname, help, NULL, ECORE_GETOPT_ACTION_APPEND,  \
       {.append_type = sub_type}}
#define ECORE_GETOPT_APPEND_METAVAR(shortname, longname, help, metavar, type) \
  {shortname, longname, help, metavar, ECORE_GETOPT_ACTION_APPEND,            \
       {.append_type = type}}

#define ECORE_GETOPT_COUNT(shortname, longname, help)          \
  {shortname, longname, help, NULL, ECORE_GETOPT_ACTION_COUNT, \
       {.dummy = NULL}}

#define ECORE_GETOPT_CALLBACK_FULL(shortname, longname, help, metavar, callback_func, callback_data, argument_requirement, default_value) \
  {shortname, longname, help, metavar, ECORE_GETOPT_ACTION_CALLBACK,                                                                      \
       {.callback = {callback_func, callback_data,                                                                                        \
                     argument_requirement, default_value}}}
#define ECORE_GETOPT_CALLBACK_NOARGS(shortname, longname, help, callback_func, callback_data) \
  ECORE_GETOPT_CALLBACK_FULL(shortname, longname, help, NULL,                                 \
                             callback_func, callback_data,                                    \
                             ECORE_GETOPT_DESC_ARG_REQUIREMENT_NO,                            \
                             NULL)
#define ECORE_GETOPT_CALLBACK_ARGS(shortname, longname, help, metavar, callback_func, callback_data) \
  ECORE_GETOPT_CALLBACK_FULL(shortname, longname, help, metavar,                                     \
                             callback_func, callback_data,                                           \
                             ECORE_GETOPT_DESC_ARG_REQUIREMENT_YES,                                  \
                             NULL)

#define ECORE_GETOPT_HELP(shortname, longname)      \
  {shortname, longname, "show this message.", NULL, \
       ECORE_GETOPT_ACTION_HELP,                    \
       {.dummy = NULL}}

#define ECORE_GETOPT_VERSION(shortname, longname)      \
  {shortname, longname, "show program version.", NULL, \
       ECORE_GETOPT_ACTION_VERSION,                    \
       {.dummy = NULL}}

#define ECORE_GETOPT_COPYRIGHT(shortname, longname) \
  {shortname, longname, "show copyright.", NULL,    \
       ECORE_GETOPT_ACTION_COPYRIGHT,               \
       {.dummy = NULL}}

#define ECORE_GETOPT_LICENSE(shortname, longname) \
  {shortname, longname, "show license.", NULL,    \
       ECORE_GETOPT_ACTION_LICENSE,               \
       {.dummy = NULL}}

#define ECORE_GETOPT_SENTINEL {0, NULL, NULL, NULL, 0, {.dummy = NULL}}

#define ECORE_GETOPT_VALUE_STR(val)      {.strp = &(val)}
#define ECORE_GETOPT_VALUE_BOOL(val)     {.boolp = &(val)}
#define ECORE_GETOPT_VALUE_SHORT(val)    {.shortp = &(val)}
#define ECORE_GETOPT_VALUE_INT(val)      {.intp = &(val)}
#define ECORE_GETOPT_VALUE_LONG(val)     {.longp = &(val)}
#define ECORE_GETOPT_VALUE_USHORT(val)   {.ushortp = &(val)}
#define ECORE_GETOPT_VALUE_UINT(val)     {.uintp = &(val)}
#define ECORE_GETOPT_VALUE_ULONG(val)    {.ulongp = &(val)}
#define ECORE_GETOPT_VALUE_DOUBLE(val)   {.doublep = &(val)}
#define ECORE_GETOPT_VALUE_PTR(val)      {.ptrp = &(val)}
#define ECORE_GETOPT_VALUE_PTR_CAST(val) {.ptrp = (void **)&(val)}
#define ECORE_GETOPT_VALUE_LIST(val)     {.listp = &(val)}
#define ECORE_GETOPT_VALUE_NONE          {.ptrp = NULL}

	EAPI void ecore_getopt_help(FILE * fp, const Ecore_Getopt * info);

	EAPI unsigned char ecore_getopt_parser_has_duplicates(const
							      Ecore_Getopt
							      * parser);
	EAPI int ecore_getopt_parse(const Ecore_Getopt * parser,
				    Ecore_Getopt_Value * values, int argc,
				    char **argv);

	EAPI Eina_List *ecore_getopt_list_free(Eina_List * list);

	/* helper functions to be used with ECORE_GETOPT_CALLBACK_*() */
	EAPI unsigned char ecore_getopt_callback_geometry_parse(const
								Ecore_Getopt
								* parser,
								const
								Ecore_Getopt_Desc
								* desc,
								const char
								*str,
								void *data,
								Ecore_Getopt_Value
								* storage);
	EAPI unsigned char ecore_getopt_callback_size_parse(const
							    Ecore_Getopt *
							    parser,
							    const
							    Ecore_Getopt_Desc
							    * desc,
							    const char
							    *str,
							    void *data,
							    Ecore_Getopt_Value
							    * storage);


#ifdef __cplusplus
}
#endif
#endif				/* _ECORE_GETOPT_H */
