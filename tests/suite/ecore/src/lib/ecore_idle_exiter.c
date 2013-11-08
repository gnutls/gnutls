#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include "Ecore.h"
#include "ecore_private.h"


struct _Ecore_Idle_Exiter {
	EINA_INLIST;
	ECORE_MAGIC;
	Ecore_Task_Cb func;
	void *data;
	int references;
	Eina_Bool delete_me:1;
};


static Ecore_Idle_Exiter *idle_exiters = NULL;
static Ecore_Idle_Exiter *idle_exiter_current = NULL;
static int idle_exiters_delete_me = 0;

/**
 * Add an idle exiter handler.
 * @param func The function to call when exiting an idle state.
 * @param data The data to be passed to the @p func call
 * @return A handle to the idle exiter callback on success.  NULL otherwise.
 * @ingroup Idle_Group
 */
EAPI Ecore_Idle_Exiter *ecore_idle_exiter_add(Ecore_Task_Cb func,
					      const void *data)
{
	Ecore_Idle_Exiter *ie;

	if (!func)
		return NULL;
	ie = calloc(1, sizeof(Ecore_Idle_Exiter));
	if (!ie)
		return NULL;
	ECORE_MAGIC_SET(ie, ECORE_MAGIC_IDLE_EXITER);
	ie->func = func;
	ie->data = (void *) data;
	idle_exiters =
	    (Ecore_Idle_Exiter *)
	    eina_inlist_append(EINA_INLIST_GET(idle_exiters),
			       EINA_INLIST_GET(ie));
	return ie;
}

/**
 * Delete an idle exiter handler from the list to be run on exiting idle state.
 * @param idle_exiter The idle exiter to delete
 * @return The data pointer that was being being passed to the handler if
 *         successful.  NULL otherwise.
 * @ingroup Idle_Group
 */
EAPI void *ecore_idle_exiter_del(Ecore_Idle_Exiter * idle_exiter)
{
	if (!ECORE_MAGIC_CHECK(idle_exiter, ECORE_MAGIC_IDLE_EXITER)) {
		ECORE_MAGIC_FAIL(idle_exiter, ECORE_MAGIC_IDLE_EXITER,
				 "ecore_idle_exiter_del");
		return NULL;
	}
	EINA_SAFETY_ON_TRUE_RETURN_VAL(idle_exiter->delete_me, NULL);
	idle_exiter->delete_me = 1;
	idle_exiters_delete_me = 1;
	return idle_exiter->data;
}

void _ecore_idle_exiter_shutdown(void)
{
	Ecore_Idle_Exiter *ie;
	while ((ie = idle_exiters)) {
		idle_exiters =
		    (Ecore_Idle_Exiter *)
		    eina_inlist_remove(EINA_INLIST_GET(idle_exiters),
				       EINA_INLIST_GET(idle_exiters));
		ECORE_MAGIC_SET(ie, ECORE_MAGIC_NONE);
		free(ie);
	}
	idle_exiters_delete_me = 0;
	idle_exiter_current = NULL;
}

void _ecore_idle_exiter_call(void)
{
	if (!idle_exiter_current) {
		/* regular main loop, start from head */
		idle_exiter_current = idle_exiters;
	} else {
		/* recursive main loop, continue from where we were */
		idle_exiter_current =
		    (Ecore_Idle_Exiter *)
		    EINA_INLIST_GET(idle_exiter_current)->next;
	}

	while (idle_exiter_current) {
		Ecore_Idle_Exiter *ie =
		    (Ecore_Idle_Exiter *) idle_exiter_current;
		if (!ie->delete_me) {
			ie->references++;
			if (!ie->func(ie->data)) {
				if (!ie->delete_me)
					ecore_idle_exiter_del(ie);
			}
			ie->references--;
		}
		if (idle_exiter_current)	/* may have changed in recursive main loops */
			idle_exiter_current =
			    (Ecore_Idle_Exiter *)
			    EINA_INLIST_GET(idle_exiter_current)->next;
	}
	if (idle_exiters_delete_me) {
		Ecore_Idle_Exiter *l;
		int deleted_idler_exiters_in_use = 0;

		for (l = idle_exiters; l;) {
			Ecore_Idle_Exiter *ie = l;

			l = (Ecore_Idle_Exiter *) EINA_INLIST_GET(l)->next;
			if (ie->delete_me) {
				if (ie->references) {
					deleted_idler_exiters_in_use++;
					continue;
				}

				idle_exiters =
				    (Ecore_Idle_Exiter *)
				    eina_inlist_remove(EINA_INLIST_GET
						       (idle_exiters),
						       EINA_INLIST_GET
						       (ie));
				ECORE_MAGIC_SET(ie, ECORE_MAGIC_NONE);
				free(ie);
			}
		}
		if (!deleted_idler_exiters_in_use)
			idle_exiters_delete_me = 0;
	}
}

int _ecore_idle_exiter_exist(void)
{
	if (idle_exiters)
		return 1;
	return 0;
}
