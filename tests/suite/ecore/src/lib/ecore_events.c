#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include "Ecore.h"
#include "ecore_private.h"

static int inpurge = 0;

struct _Ecore_Event_Handler {
	EINA_INLIST;
	ECORE_MAGIC;
	int type;
	Ecore_Event_Handler_Cb func;
	void *data;
	int references;
	Eina_Bool delete_me:1;
};

struct _Ecore_Event_Filter {
	EINA_INLIST;
	ECORE_MAGIC;
	Ecore_Data_Cb func_start;
	Ecore_Filter_Cb func_filter;
	Ecore_End_Cb func_end;
	void *loop_data;
	void *data;
	int references;
	Eina_Bool delete_me:1;
};

struct _Ecore_Event {
	EINA_INLIST;
	ECORE_MAGIC;
	int type;
	void *event;
	Ecore_End_Cb func_free;
	void *data;
	int references;
	Eina_Bool delete_me:1;
};


static int events_num = 0;
static Ecore_Event *events = NULL;
static Ecore_Event *event_current = NULL;
static Ecore_Event *purge_events = NULL;

static Ecore_Event_Handler **event_handlers = NULL;
static Ecore_Event_Handler *event_handler_current = NULL;
static int event_handlers_num = 0;
static int event_handlers_alloc_num = 0;
static Eina_List *event_handlers_delete_list = NULL;

static Ecore_Event_Filter *event_filters = NULL;
static Ecore_Event_Filter *event_filter_current = NULL;
static Ecore_Event *event_filter_event_current = NULL;
static int event_filters_delete_me = 0;
static int event_id_max = ECORE_EVENT_COUNT;
static int ecore_raw_event_type = ECORE_EVENT_NONE;
static void *ecore_raw_event_event = NULL;


static void _ecore_event_purge_deleted(void);
static void *_ecore_event_del(Ecore_Event * event);


/**
 * Add an event handler.
 * @param type The type of the event this handler will get called for
 * @param func The function to call when the event is found in the queue
 * @param data A data pointer to pass to the called function @p func
 * @return A new Event handler, or NULL on failure
 *
 * Add an event handler to the list of handlers. This will, on success, return
 * a handle to the event handler object that was created, that can be used
 * later to remove the handler using ecore_event_handler_del(). The @p type
 * parameter is the integer of the event type that will trigger this callback
 * to be called. The callback @p func is called when this event is processed
 * and will be passed the event type, a pointer to the private event
 * structure that is specific to that event type, and a data pointer that is
 * provided in this call as the @p data parameter.
 *
 * When the callback @p func is called, it must return 1 or 0. If it returns
 * 1 (or ECORE_CALLBACK_RENEW), It will keep being called as per normal, for
 * each handler set up for that event type. If it returns 0 (or
 * ECORE_CALLBACK_CANCEL), it will cease processing handlers for that particular
 * event, so all handler set to handle that event type that have not already
 * been called, will not be.
 */
EAPI Ecore_Event_Handler *ecore_event_handler_add(int type,
						  Ecore_Event_Handler_Cb
						  func, const void *data)
{
	Ecore_Event_Handler *eh;

	if (!func)
		return NULL;
	if ((type <= ECORE_EVENT_NONE) || (type >= event_id_max))
		return NULL;
	eh = calloc(1, sizeof(Ecore_Event_Handler));
	if (!eh)
		return NULL;
	ECORE_MAGIC_SET(eh, ECORE_MAGIC_EVENT_HANDLER);
	eh->type = type;
	eh->func = func;
	eh->data = (void *) data;
	if (type >= (event_handlers_num - 1)) {
		int p_alloc_num;

		p_alloc_num = event_handlers_alloc_num;
		event_handlers_num = type + 1;
		if (event_handlers_num > event_handlers_alloc_num) {
			Ecore_Event_Handler **new_handlers;
			int i;

			event_handlers_alloc_num =
			    ((event_handlers_num + 16) / 16) * 16;
			new_handlers =
			    realloc(event_handlers,
				    event_handlers_alloc_num *
				    sizeof(Ecore_Event_Handler *));
			if (!new_handlers) {
				free(eh);
				return NULL;
			}
			event_handlers = new_handlers;
			for (i = p_alloc_num; i < event_handlers_alloc_num;
			     i++)
				event_handlers[i] = NULL;
		}
	}
	event_handlers[type] =
	    (Ecore_Event_Handler *)
	    eina_inlist_append(EINA_INLIST_GET(event_handlers[type]),
			       EINA_INLIST_GET(eh));
	return eh;
}

/**
 * Delete an event handler.
 * @param event_handler Event handler handle to delete
 * @return Data passed to handler
 *
 * Delete a specified event handler from the handler list. On success this will
 * delete the event handler and return the pointer passed as @p data when the
 * handler was added by ecore_event_handler_add(). On failure NULL will be
 * returned. Once a handler is deleted it will no longer be called.
 */
EAPI void *ecore_event_handler_del(Ecore_Event_Handler * event_handler)
{
	if (!ECORE_MAGIC_CHECK(event_handler, ECORE_MAGIC_EVENT_HANDLER)) {
		ECORE_MAGIC_FAIL(event_handler, ECORE_MAGIC_EVENT_HANDLER,
				 "ecore_event_handler_del");
		return NULL;
	}
	EINA_SAFETY_ON_TRUE_RETURN_VAL(event_handler->delete_me, NULL);
	event_handler->delete_me = 1;
	event_handlers_delete_list =
	    eina_list_append(event_handlers_delete_list, event_handler);
	return event_handler->data;
}

static void _ecore_event_generic_free(void *data __UNUSED__, void *event)
{
	free(event);
}

/**
 * Add an event to the event queue.
 * @param type The event type to add to the end of the event queue
 * @param ev The private data structure for this event type
 * @param func_free The function to be called to free this private structure
 * @param data The data pointer to be passed to the free function
 * @return A Handle for that event
 *
 * On success this function returns a handle to an event on the event queue, or
 * NULL if it fails. If it succeeds, an event of type @p type will be added
 * to the queue for processing by event handlers added by
 * ecore_event_handler_add(). The @p ev parameter will be a pointer to the event
 * private data that is specific to that event type. When the event is no
 * longer needed, @p func_free will be called and passed the private structure
 * pointer for cleaning up. If @p func_free is NULL, free() will be called
 * with the private structure pointer.
 * func_free is passed @p data as its data parameter.
 */
EAPI Ecore_Event *ecore_event_add(int type, void *ev,
				  Ecore_End_Cb func_free, void *data)
{
/*   if (!ev) return NULL;*/
	if (type <= ECORE_EVENT_NONE)
		return NULL;
	if (type >= event_id_max)
		return NULL;
	if ((ev) && (!func_free))
		func_free = _ecore_event_generic_free;
	return _ecore_event_add(type, ev, func_free, data);
}

/**
 * Delete an event from the queue.
 * @param event The event handle to delete
 * @return The data pointer originally set for the event free function
 *
 * This deletes the event @p event from the event queue, and returns the
 * @p data parameer originally set when adding it with ecore_event_add(). This
 * does not immediately call the free function, and it may be called later on
 * cleanup, and so if the free function depends on the data pointer to work,
 * you should defer cleaning of this till the free function is called later.
 */
EAPI void *ecore_event_del(Ecore_Event * event)
{
	if (!ECORE_MAGIC_CHECK(event, ECORE_MAGIC_EVENT)) {
		ECORE_MAGIC_FAIL(event, ECORE_MAGIC_EVENT,
				 "ecore_event_del");
		return NULL;
	}
	EINA_SAFETY_ON_TRUE_RETURN_VAL(event->delete_me, NULL);
	event->delete_me = 1;
	return event->data;
}

/**
 * Allocate a new event type id sensibly and return the new id.
 * @return A new event type id.
 *
 * This function allocates a new event type id and returns it. Once an event
 * type has been allocated it can never be de-allocated during the life of
 * the program. There is no guarantee of the contents of this event ID, or how
 * it is calculated, except that the ID will be unique to the current instance
 * of the process.
 */
EAPI int ecore_event_type_new(void)
{
	event_id_max++;
	return event_id_max - 1;
}

/**
 * Add a filter the current event queue.
 * @param func_start Function to call just before filtering and return data
 * @param func_filter Function to call on each event
 * @param func_end Function to call after the queu has been filtered
 * @param data Data to pass to the filter functions
 * @return A filter handle
 *
 * This adds a filter to call callbacks to loop through the event queue and
 * filter events out of the queue. On failure NULL is returned. On success a
 * Filter handle is returned. Filters are called on the queue just before
 * Event handler processing to try and remove redundant events. Just as
 * processing starts @p func_start is called and passed the @p data pointer.
 * This function returns a pointer that is used as loop_data that is now passed to
 * @p func_filter as loop_data. @p func_filter is also passed @p data and the
 * event type and private event structure. If this callback returns 0, the
 * event is removed from the queue. If it returns 1, the event is kept. When
 * processing is finished @p func_end is called and is passed the loop_data
 * and @p data pointer to clean up.
 */
EAPI Ecore_Event_Filter *ecore_event_filter_add(Ecore_Data_Cb func_start,
						Ecore_Filter_Cb
						func_filter,
						Ecore_End_Cb func_end,
						const void *data)
{
	Ecore_Event_Filter *ef;

	if (!func_filter)
		return NULL;
	ef = calloc(1, sizeof(Ecore_Event_Filter));
	if (!ef)
		return NULL;
	ECORE_MAGIC_SET(ef, ECORE_MAGIC_EVENT_FILTER);
	ef->func_start = func_start;
	ef->func_filter = func_filter;
	ef->func_end = func_end;
	ef->data = (void *) data;
	event_filters =
	    (Ecore_Event_Filter *)
	    eina_inlist_append(EINA_INLIST_GET(event_filters),
			       EINA_INLIST_GET(ef));
	return ef;
}

/**
 * Delete an event filter.
 * @param ef The event filter handle
 * @return The data set for the filter
 *
 * Delete a filter that has been added by its @p ef handle. On success this
 * will return the data pointer set when this filter was added. On failure
 * NULL is returned.
 */
EAPI void *ecore_event_filter_del(Ecore_Event_Filter * ef)
{
	if (!ECORE_MAGIC_CHECK(ef, ECORE_MAGIC_EVENT_FILTER)) {
		ECORE_MAGIC_FAIL(ef, ECORE_MAGIC_EVENT_FILTER,
				 "ecore_event_filter_del");
		return NULL;
	}
	EINA_SAFETY_ON_TRUE_RETURN_VAL(ef->delete_me, NULL);
	ef->delete_me = 1;
	event_filters_delete_me = 1;
	return ef->data;
}

/**
 * Return the current event type being handled.
 * @return The current event type being handled if inside a handler callback
 *
 * If the program is currently inside an Ecore event handler callback this
 * will return the type of the current event being processed. If Ecore is
 * not inside an event handler, ECORE_EVENT_NONE is returned.
 *
 * This is useful when certain Ecore modules such as Ecore_Evas "swallow"
 * events and not all the original information is passed on. In special cases
 * this extra information may be useful or needed and using this call can let
 * the program know if the event type being handled is one it wants to get more
 * information about.
 */
EAPI int ecore_event_current_type_get(void)
{
	return ecore_raw_event_type;
}

/**
 * Return the current event type pointer handled.
 * @return The current event pointer being handled if inside a handler callback
 *
 * If the program is currently inside an Ecore event handler callback this
 * will return the pointer of the current event being processed. If Ecore is
 * not inside an event handler, NULL will be returned.
 *
 * This is useful when certain Ecore modules such as Ecore_Evas "swallow"
 * events and not all the original information is passed on. In special cases
 * this extra information may be useful or needed and using this call can let
 * the program access the event data if the type of the event is handled by
 * the program.
 */
EAPI void *ecore_event_current_event_get(void)
{
	return ecore_raw_event_event;
}

void _ecore_event_shutdown(void)
{
	int i;
	Ecore_Event_Handler *eh;
	Ecore_Event_Filter *ef;

	while (events)
		_ecore_event_del(events);
	event_current = NULL;
	for (i = 0; i < event_handlers_num; i++) {
		while ((eh = event_handlers[i])) {
			event_handlers[i] =
			    (Ecore_Event_Handler *)
			    eina_inlist_remove(EINA_INLIST_GET
					       (event_handlers[i]),
					       EINA_INLIST_GET
					       (event_handlers[i]));
			ECORE_MAGIC_SET(eh, ECORE_MAGIC_NONE);
			if (!eh->delete_me)
				free(eh);
		}
	}
	EINA_LIST_FREE(event_handlers_delete_list, eh)
	    free(eh);
	if (event_handlers)
		free(event_handlers);
	event_handlers = NULL;
	event_handlers_num = 0;
	event_handlers_alloc_num = 0;
	while ((ef = event_filters)) {
		event_filters =
		    (Ecore_Event_Filter *)
		    eina_inlist_remove(EINA_INLIST_GET(event_filters),
				       EINA_INLIST_GET(event_filters));
		ECORE_MAGIC_SET(ef, ECORE_MAGIC_NONE);
		free(ef);
	}
	event_filters_delete_me = 0;
	event_filter_current = NULL;
	event_filter_event_current = NULL;
}

int _ecore_event_exist(void)
{
	Ecore_Event *e;
	EINA_INLIST_FOREACH(events, e)
	    if (!e->delete_me)
		return 1;
	return 0;
}

Ecore_Event *_ecore_event_add(int type, void *ev, Ecore_End_Cb func_free,
			      void *data)
{
	Ecore_Event *e;

	e = calloc(1, sizeof(Ecore_Event));
	if (!e)
		return NULL;
	ECORE_MAGIC_SET(e, ECORE_MAGIC_EVENT);
	e->type = type;
	e->event = ev;
	e->func_free = func_free;
	e->data = data;
	if (inpurge > 0) {
		purge_events =
		    (Ecore_Event *)
		    eina_inlist_append(EINA_INLIST_GET(purge_events),
				       EINA_INLIST_GET(e));
		events_num++;
	} else {
		events =
		    (Ecore_Event *)
		    eina_inlist_append(EINA_INLIST_GET(events),
				       EINA_INLIST_GET(e));
		events_num++;
	}
	return e;
}

void *_ecore_event_del(Ecore_Event * event)
{
	void *data;

	data = event->data;
	if (event->func_free)
		event->func_free(event->data, event->event);
	events =
	    (Ecore_Event *) eina_inlist_remove(EINA_INLIST_GET(events),
					       EINA_INLIST_GET(event));
	ECORE_MAGIC_SET(event, ECORE_MAGIC_NONE);
	free(event);
	events_num--;
	return data;
}

static void _ecore_event_purge_deleted(void)
{
	Ecore_Event *itr = events;

	inpurge++;
	while (itr) {
		Ecore_Event *next =
		    (Ecore_Event *) EINA_INLIST_GET(itr)->next;
		if ((!itr->references) && (itr->delete_me))
			_ecore_event_del(itr);
		itr = next;
	}
	inpurge--;
	while (purge_events) {
		Ecore_Event *e = purge_events;
		purge_events =
		    (Ecore_Event *)
		    eina_inlist_remove(EINA_INLIST_GET(purge_events),
				       EINA_INLIST_GET(purge_events));
		events =
		    (Ecore_Event *)
		    eina_inlist_append(EINA_INLIST_GET(events),
				       EINA_INLIST_GET(e));
	}
}

static inline void _ecore_event_filters_apply()
{

	if (!event_filter_current) {
		/* regular main loop, start from head */
		event_filter_current = event_filters;
	} else {
		/* recursive main loop, continue from where we were */
		event_filter_current =
		    (Ecore_Event_Filter *)
		    EINA_INLIST_GET(event_filter_current)->next;
	}

	while (event_filter_current) {
		Ecore_Event_Filter *ef = event_filter_current;

		if (!ef->delete_me) {
			ef->references++;

			if (ef->func_start)
				ef->loop_data = ef->func_start(ef->data);

			if (!event_filter_event_current) {
				/* regular main loop, start from head */
				event_filter_event_current = events;
			} else {
				/* recursive main loop, continue from where we were */
				event_filter_event_current =
				    (Ecore_Event *)
				    EINA_INLIST_GET
				    (event_filter_event_current)->next;
			}

			while (event_filter_event_current) {
				Ecore_Event *e =
				    event_filter_event_current;

				if (!ef->
				    func_filter(ef->data, ef->loop_data,
						e->type, e->event)) {
					ecore_event_del(e);
				}

				if (event_filter_event_current)	/* may have changed in recursive main loops */
					event_filter_event_current =
					    (Ecore_Event *)
					    EINA_INLIST_GET
					    (event_filter_event_current)->
					    next;
			}
			if (ef->func_end)
				ef->func_end(ef->data, ef->loop_data);

			ef->references--;
		}

		if (event_filter_current)	/* may have changed in recursive main loops */
			event_filter_current =
			    (Ecore_Event_Filter *)
			    EINA_INLIST_GET(event_filter_current)->next;
	}
	if (event_filters_delete_me) {
		int deleted_in_use = 0;
		Ecore_Event_Filter *l;
		for (l = event_filters; l;) {
			Ecore_Event_Filter *ef = l;
			l = (Ecore_Event_Filter *) EINA_INLIST_GET(l)->
			    next;
			if (ef->delete_me) {
				if (ef->references) {
					deleted_in_use++;
					continue;
				}

				event_filters =
				    (Ecore_Event_Filter *)
				    eina_inlist_remove(EINA_INLIST_GET
						       (event_filters),
						       EINA_INLIST_GET
						       (ef));
				ECORE_MAGIC_SET(ef, ECORE_MAGIC_NONE);
				free(ef);
			}
		}
		if (!deleted_in_use)
			event_filters_delete_me = 0;
	}
}

void _ecore_event_call(void)
{
	Eina_List *l, *l_next;
	Ecore_Event_Handler *eh;

	_ecore_event_filters_apply();

	if (!event_current) {
		/* regular main loop, start from head */
		event_current = events;
		event_handler_current = NULL;
	}

	while (event_current) {
		Ecore_Event *e = event_current;
		int handle_count = 0;

		if (e->delete_me) {
			event_current =
			    (Ecore_Event *)
			    EINA_INLIST_GET(event_current)->next;
			continue;
		}

		ecore_raw_event_type = e->type;
		ecore_raw_event_event = e->event;
		e->references++;
		if ((e->type >= 0) && (e->type < event_handlers_num)) {
			if (!event_handler_current) {
				/* regular main loop, start from head */
				event_handler_current =
				    event_handlers[e->type];
			} else {
				/* recursive main loop, continue from where we were */
				event_handler_current =
				    (Ecore_Event_Handler *)
				    EINA_INLIST_GET
				    (event_handler_current)->next;
			}

			while ((event_handler_current) && (!e->delete_me)) {
				Ecore_Event_Handler *eh =
				    event_handler_current;
				if (!eh->delete_me) {
					Eina_Bool ret;

					handle_count++;

					eh->references++;
					ret =
					    eh->func(eh->data, e->type,
						     e->event);
					eh->references--;

					if (!ret) {
						event_handler_current =
						    NULL;
						break;	/* 0 == "call no further handlers" */
					}
				}

				if (event_handler_current)	/* may have changed in recursive main loops */
					event_handler_current =
					    (Ecore_Event_Handler *)
					    EINA_INLIST_GET
					    (event_handler_current)->next;
			}
		}
		/* if no handlers were set for EXIT signal - then default is */
		/* to quit the main loop */
		if ((e->type == ECORE_EVENT_SIGNAL_EXIT)
		    && (handle_count == 0))
			ecore_main_loop_quit();
		e->references--;
		e->delete_me = 1;

		if (event_current)	/* may have changed in recursive main loops */
			event_current =
			    (Ecore_Event *)
			    EINA_INLIST_GET(event_current)->next;
	}

	ecore_raw_event_type = ECORE_EVENT_NONE;
	ecore_raw_event_event = NULL;

	_ecore_event_purge_deleted();

	EINA_LIST_FOREACH_SAFE(event_handlers_delete_list, l, l_next, eh) {
		if (eh->references)
			continue;

		event_handlers_delete_list =
		    eina_list_remove_list(event_handlers_delete_list, l);

		event_handlers[eh->type] =
		    (Ecore_Event_Handler *)
		    eina_inlist_remove(EINA_INLIST_GET
				       (event_handlers[eh->type]),
				       EINA_INLIST_GET(eh));
		ECORE_MAGIC_SET(eh, ECORE_MAGIC_NONE);
		free(eh);
	}
}

EAPI void *_ecore_event_signal_user_new(void)
{
	Ecore_Event_Signal_User *e;

	e = calloc(1, sizeof(Ecore_Event_Signal_User));
	return e;
}

void *_ecore_event_signal_hup_new(void)
{
	Ecore_Event_Signal_Hup *e;

	e = calloc(1, sizeof(Ecore_Event_Signal_Hup));
	return e;
}

void *_ecore_event_signal_exit_new(void)
{
	Ecore_Event_Signal_Exit *e;

	e = calloc(1, sizeof(Ecore_Event_Signal_Exit));
	return e;
}

void *_ecore_event_signal_power_new(void)
{
	Ecore_Event_Signal_Power *e;

	e = calloc(1, sizeof(Ecore_Event_Signal_Power));
	return e;
}

void *_ecore_event_signal_realtime_new(void)
{
	return calloc(1, sizeof(Ecore_Event_Signal_Realtime));
}
