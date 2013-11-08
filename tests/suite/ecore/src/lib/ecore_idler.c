#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include "Ecore.h"
#include "ecore_private.h"


struct _Ecore_Idler {
	EINA_INLIST;
	ECORE_MAGIC;
	Ecore_Task_Cb func;
	void *data;
	int references;
	Eina_Bool delete_me:1;
};


static Ecore_Idler *idlers = NULL;
static Ecore_Idler *idler_current = NULL;
static int idlers_delete_me = 0;

/**
 * Add an idler handler.
 * @param  func The function to call when idling.
 * @param  data The data to be passed to this @p func call.
 * @return A idler handle if successfully added.  NULL otherwise.
 * @ingroup Idle_Group
 *
 * Add an idler handle to the event loop, returning a handle on success and
 * NULL otherwise.  The function @p func will be called repeatedly while
 * no other events are ready to be processed, as long as it returns 1
 * (or ECORE_CALLBACK_RENEW). A return of 0 (or ECORE_CALLBACK_CANCEL) deletes
 * the idler.
 *
 * Idlers are useful for progressively prossessing data without blocking.
 */
EAPI Ecore_Idler *ecore_idler_add(Ecore_Task_Cb func, const void *data)
{
	Ecore_Idler *ie;

	if (!func)
		return NULL;
	ie = calloc(1, sizeof(Ecore_Idler));
	if (!ie)
		return NULL;
	ECORE_MAGIC_SET(ie, ECORE_MAGIC_IDLER);
	ie->func = func;
	ie->data = (void *) data;
	idlers =
	    (Ecore_Idler *) eina_inlist_append(EINA_INLIST_GET(idlers),
					       EINA_INLIST_GET(ie));
	return ie;
}

/**
 * Delete an idler callback from the list to be executed.
 * @param  idler The handle of the idler callback to delete
 * @return The data pointer passed to the idler callback on success.  NULL
 *         otherwise.
 * @ingroup Idle_Group
 */
EAPI void *ecore_idler_del(Ecore_Idler * idler)
{
	if (!ECORE_MAGIC_CHECK(idler, ECORE_MAGIC_IDLER)) {
		ECORE_MAGIC_FAIL(idler, ECORE_MAGIC_IDLER,
				 "ecore_idler_del");
		return NULL;
	}
	EINA_SAFETY_ON_TRUE_RETURN_VAL(idler->delete_me, NULL);
	idler->delete_me = 1;
	idlers_delete_me = 1;
	return idler->data;
}

void _ecore_idler_shutdown(void)
{
	Ecore_Idler *ie;
	while ((ie = idlers)) {
		idlers =
		    (Ecore_Idler *)
		    eina_inlist_remove(EINA_INLIST_GET(idlers),
				       EINA_INLIST_GET(idlers));
		ECORE_MAGIC_SET(ie, ECORE_MAGIC_NONE);
		free(ie);
	}
	idlers_delete_me = 0;
	idler_current = NULL;
}

int _ecore_idler_call(void)
{
	if (!idler_current) {
		/* regular main loop, start from head */
		idler_current = idlers;
	} else {
		/* recursive main loop, continue from where we were */
		idler_current =
		    (Ecore_Idler *) EINA_INLIST_GET(idler_current)->next;
	}

	while (idler_current) {
		Ecore_Idler *ie = (Ecore_Idler *) idler_current;
		if (!ie->delete_me) {
			ie->references++;
			if (!ie->func(ie->data)) {
				if (!ie->delete_me)
					ecore_idler_del(ie);
			}
			ie->references--;
		}
		if (idler_current)	/* may have changed in recursive main loops */
			idler_current =
			    (Ecore_Idler *)
			    EINA_INLIST_GET(idler_current)->next;
	}
	if (idlers_delete_me) {
		Ecore_Idler *l;
		int deleted_idlers_in_use = 0;
		for (l = idlers; l;) {
			Ecore_Idler *ie = l;
			l = (Ecore_Idler *) EINA_INLIST_GET(l)->next;
			if (ie->delete_me) {
				if (ie->references) {
					deleted_idlers_in_use++;
					continue;
				}

				idlers =
				    (Ecore_Idler *)
				    eina_inlist_remove(EINA_INLIST_GET
						       (idlers),
						       EINA_INLIST_GET
						       (ie));
				ECORE_MAGIC_SET(ie, ECORE_MAGIC_NONE);
				free(ie);
			}
		}
		if (!deleted_idlers_in_use)
			idlers_delete_me = 0;
	}
	if (idlers)
		return 1;
	return 0;
}

int _ecore_idler_exist(void)
{
	if (idlers)
		return 1;
	return 0;
}
