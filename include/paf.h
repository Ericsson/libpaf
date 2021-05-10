/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2021 Ericsson AB
 */

#ifndef PAF_H
#define PAF_H
#ifdef __cplusplus
extern "C" {
#endif

/*! @mainpage Pathfinder Client Library API
 *
 * @tableofcontents
 *
 * This is the documentation for the Pathfinder Client Library API.
 *
 * - paf.h Core functionality
 * - paf_props.h Service property access.
 * - paf_value.h Property value.
 * - paf_err.h Error handling.
 * - paf_match.h Subscription matching.
 *
 * @author Mattias Rönnblom
 * @version 0.0 [API]
 * @version 1.0.1 [Implementation]
 *
 * @section overview Overview
 *
 * The Pathfinder Client Library API is used to access one or more
 * Pathfinder service discovery domains, either as a service producer
 * or consumer.
 *
 * All the functions in this API are non-blocking in the sense that no
 * blocking system calls are made.
 *
 * For simplicity, the library implementing this API is referred to as
 * @c libpaf, although there might be other implementations as well.
 *
 * @section domains Service Discovery Domains
 *
 * A Pathfinder service discovery domain is a namespace shared by all
 * Pathfinder clients attached to that domain. A service publish by
 * one client can be seen by all other clients attached to that
 * domain. A domain is served by one or more Pathfinder server
 * instances.
 *
 * In order to participate in a domain, an application issues
 * paf_attach() with the appropriate service discovery domain name. It
 * need not know what servers are currently serving that domain.
 *
 * @subsection domain_mapping Domain Configuration
 *
 * The mapping between a service discovery domain name and the set of
 * addresses to the Pathfinder servers serving this domain is kept in
 * a file. The configuration for a particular domain name must be
 * stored in a file with the same name as the domain, and be located
 * in the domain files directory.  The compile-time default location
 * is is @c /run/paf/domains.d/.
 *
 * The directory may contain an arbitrary number of domains.
 *
 * In case the domain file does not exist at the time of the
 * paf_attach() call, @c libpaf will periodically check if it has been
 * created.
 *
 * In case the file is modified (e.g., a server is added, removed or
 * has its address changed), the file will be re-read by @c libpaf.
 * If the file is removed, the set of servers is considered empty.
 *
 * The environment variable @c PAF_DOMAINS may set in case a
 * non-standard directory is preferred over the default.
 *
 * @subsubsection domain_file_format File Format
 * 
 * @c libpaf supports two file formats. Either the contents of the
 * file is a newline-separated list of XCM addresses, or a JSON
 * object.
 *
 * The newline-separated format allows for comments. In this format,
 * empty lines and lines beginning with '#' are ignored. JSON does not
 * support comments.
 *
 * A domain file in the JSON format must contain a root JSON object,
 * with a key "servers". The value of "servers" must be an array of
 * zero or more JSON objects, each representing a server.
 *
 * The server object must have a key "address", with a string value.
 *
 * In case the transport protocol uses TLS, three optional keys may be
 * present in the server object:
 *
 * - "tlsCertificateFile": the leaf certificate to use.
 * - "tlsKeyFile": the private key corresponding to the leaf certificate.
 * - "tlsTrustedCaFile": a file containing the trusted CA certificates.
 *
 * In case some/all of the certificate file related keys are left out,
 * @c libpaf will fall back to using the XCM defaults.
 *
 * Below is an example of a domain file in JSON format:
 * @code
 * {
 *   "servers": [
 *     {
 *       "address": "tls:1.2.3.4:4444",
 *       "tlsCertificateFile": "/etc/paf/certs/cert.pem",
 *       "tlsKeyFile": "/etc/paf/certs/key.pem",
 *       "tlsTrustedCaFile": "/etc/paf/certs/ca-bundle.pem"
 *     },
 *     {
 *       "address": "tls:5.6.7.8:8888"
 *     },
 *     {
 *       "address": "ux:foo"
 *     }
 *   ]
 * }
 * @endcode
 * 
 * The same configuration (minus the certificate-related
 * configuration), but in the newline-separated format:
 * @code
 * "tls:1.2.3.4:4444"
 * "tls:5.6.7.8:8888"
 * "ux:foo"
 * @endcode
 *
 * @subsubsection rescan Domain File Rescan
 *
 * For all domains the application currently has attached to, @c
 * libpaf tracks domain file changes. This check is performed
 * periodically every ~5 s. A small random component is added to avoid
 * load spikes, in case there are many clients on the same system.
 *
 * This default interval may be changed by setting the @c PAF_RESCAN
 * environment variable. The value a floating point number (in s). If
 * set to zero, the rescanning is disabled.
 *
 * @section reconnect Connection Reestablishment
 *
 * In case the connection to a server is lost, or never was
 * successfully established in the first place, @c libpaf will perform
 * another attempt at a later time.
 *
 * @c libpaf uses exponential back-off. The first retry is scheduled
 * to occur after 10 ms. Every failed attempt double the retry
 * interval, up to a maximum of 5 s. These two defaults may be changed
 * by setting the @c PAF_RECONNECT_MIN and/or @c PAF_RECONNECT_MAX
 * environment variables.
 *
 * @section ttl Service TTL
 *
 * A service publish via the library has a time-to-live (TTL) of 30
 * s. This default may be changed by setting the @c PAF_TTL
 * environment variable, beforing the paf_publish() call. The TTL must
 * be an non-negative integer.
 *
 * @section tracing Tracing
 *
 * @c libpaf comes with built-in support for tracing. The library
 * supports writing traces to stderr in human-readable format, or
 * direct them to LTTng. The former is always available, and the
 * latter is available if the library is built with LTTng support.
 *
 * To enable stderr-type tracing, set the @c PAF_DEBUG environment
 * variable to "1", before starting the application.
 *
 * To enabled LTTng tracing, enable the relevant libpaf LTTng
 * tracepoints.
 *
 * @section thread_safety Multi-thread Safety
 *
 * All API calls are multi-thread (MT) safe when called on different
 * context (for paf.h API calls) or service properties (for
 * paf_props.h API calls). Thus, one thread may safely call
 * paf_publish(), while another thread calls the same (or a different)
 * paf_*() function, but on another context.
 *
 * No API calls are MT safe when called on the same context or service
 * properties. For that to work, external synchronization (e.g., a
 * mutex lock) is required.
 */

/*!
 * @file paf.h
 * @brief Core Pathfinder Client Library API.
 */

#include <stdint.h>
#include <sys/types.h>

#include <paf_props.h>
#include <paf_match.h>
#include <paf_err.h>

struct paf_context;

/**
 * Attach to a domain.
 *
 * This function attaches to a Pathfinder domain. The return value is
 * a context, which is used to store library-internal service and
 * subscription state as handed to it by the application, and
 * subscription matches from a remote server, as well as
 * protocol-related state for server communication.
 *
 * paf_attach() will succeed even though the domain doesn't currently
 * exists on the local system. Any remote communication failure, to
 * the extent any such happens during paf_attach(), also doesn't make
 * the call fail.
 *
 * @param[in] domain_name The name of the Pathfinder domain.
 *
 * @return Returns a context reference on success, or NULL if the
 *         system didn't have adequate resources to fulfill the request.
 */
struct paf_context *paf_attach(const char *domain_name);

/**
 * Publish a service.
 *
 * This function allows the application to inform the library of a
 * service it wishes to have published at any time the context has an
 * connection to a server, serving that domain.
 *
 * The successful return of paf_publish() indicates that the service
 * as been accepted into the library's context. It does not mean that
 * the service has yet been successfully published in a server, or
 * even that there is a connection to a server.
 *
 * @param[in] context A reference to the domain where the service should be published.
 * @param[in] props The properties of this service. Must be non-NULL, but may be an empty set.
 *
 * @return Returns a unique id for this service on success, or < 0 or failure.
 *
 * Return Code             | Description
 * ------------------------|------------
 * PAF_ERR_PROPS_TOO_LARGE | The service properties' maximum size was exceeded.
 */
int64_t paf_publish(struct paf_context *context, const struct paf_props *props);

/**
 * Modify a service's properties.
 *
 * This function modifies an already-published service's properties.
 *
 * The successful return of this function means the changes has been
 * commited in the supplied context, but does not mean they have
 * propagated further (i.e to the server or to any other client,
 * including subscriptions issued via this context).
 *
 * The properties supplied in @p props will replace those currently in
 * use by the service. Thus, all previous properties will be removed, and
 * replaced in their entirety by those in @p props.
 *
 * Only services published using the supplied @p context may be
 * modified.
 *
 * @param[in] context A reference to the service's domain.
 * @param[in] service_id The id of the service as returned by paf_publish().
 * @param[in] props The properties that should replace the service current properties.
 *
 * @return Returns 0 on success, or < 0 or failure.
 *
 * Return Code             | Description
 * ------------------------|------------
 * PAF_ERR_PROPS_TOO_LARGE | The service properties maxiumum size was been exceeded.
 */
int paf_modify(struct paf_context *context, int64_t service_id,
               const struct paf_props *props);

/**
 * Unpublish a service.
 *
 * This function allows the application to inform the library of a
 * Pathfinder service it wishes to have a previously published service
 * removed.
 *
 * In case the service is currently published in a server, it may not
 * yet have been removed at the time of paf_unpublish() call
 * completion. There might not event be a connection to the server
 * (where the service may still be lingering in an orphan state).
 *
 * Only services published using the supplied @p context may be
 * unpublished.
 *
 * @param[in] context A reference to the context in where the service was published.
 * @param[in] service_id The id of the service as returned by paf_publish().
 */
void paf_unpublish(struct paf_context *context, int64_t service_id);

/**
 * Issue a service subscription.
 *
 * This function registers a service subscription in the supplied context.
 *
 * The filter can be used to specify what services are interesting to
 * the application.
 *
 * The filter syntax is similar to that of LDAP (see RFC 2254), but
 * with some differences, mainly in the area of the escaping mechanism
 * (allowing special characters in search filter name or values).
 *
 * A search filter example: <tt> (&(name=my-service)(area=51)) </tt>
 *
 * Supplying NULL in @p filter will results in a "match all" filter.
 *
 * In case of a matching service appearing, is being modified, or
 * disappeared, the @p match_cb function will be called. The callback
 * function will only be called at the time of paf_process(). See @ref
 * paf_match_cb and @ref paf_match_type for more information.
 *
 * The successful return of paf_subscribe() does not guarantee that
 * the subscription has been forwarded to a server.
 *
 * @param[in] context A reference to the domain in which the subscription should be issued.
 * @param[in] filter A search filter in string format, or NULL.
 * @param[in] match_cb The callback used to notify the application of a matching service.
 * @param[in] user A user-supplied opaque pointer which will be supplied back to the application at every match callback call.
 *
 * @return Returns a unique id for this subscription on success, or < 0 or failure.
 *
 * Return Code                   | Description
 * ------------------------------|------------
 * PAF_ERR_FILTER_TOO_LARGE      | The filter exceeds the maximum size.
 * PAF_ERR_INVALID_FILTER_SYNTAX | Invalid filter syntax.
 */
int64_t paf_subscribe(struct paf_context *context, const char *filter,
                      paf_match_cb match_cb, void *user);

/**
 * Unsubscribe to a service.
 *
 * This function cancels a subscription previously issued in the
 * supplied @p context.
 *
 * After paf_unsubscribe() call completition, the corresponding
 * callback will no longer be called.
 *
 * @param[in] context A reference to the context in where the subscription was issued.
 * @param[in] subscription_id The id of the subscription as returned by paf_subscribe().
 */
void paf_unsubscribe(struct paf_context *context, int64_t subscription_id);

/**
 * Query a context for it's file descriptor.
 *
 * The file descriptor returned by this function allows the context to
 * signal when a call paf_process() is likely to allow it to make
 * progress. Progress here means things like receiving and processing
 * Pathfinder wire protocol messages, handling timeout, and calling
 * user callbacks.
 *
 * The application should wait for the fd to become readable (i.e. it
 * should be put into the readfds set for select(), or be marked
 * POLLIN/EPOLLIN in case poll()/epoll() is used), and then call
 * paf_process().
 *
 * The file descriptor is stable (i.e the number doesn't change)
 * across the life-time of the context. To what underlying file
 * description it's pointing also doesn't change (a detail relevent
 * for its use in epoll()). The fd is also unique to this context
 * (i.e. several context will not reuse the same fd).
 *
 * @param[in] context The context.
 *
 * @return Returns the context's file descriptor
 *
 */
int paf_fd(struct paf_context *context);

/**
 * Perform processing related to a particular context.
 *
 * This function will processing related to the supplied context. Such
 * processing can be things like establishing a connection to a
 * server, sending messages to or receiving messages from a server or
 * check for timeout on stale (orphan) services.
 *
 * As a part of paf_process() call, the library may invoke one or more
 * @ref paf_match_cb subscription callbacks. Such a callback may not
 * call back into any paf.h core API functions with the current
 * context as it's input (e.g. paf_subscribe(), paf_unsubscribe()
 * etc).
 *
 * paf_process() may be called at any point, but will typically be
 * called after select() (or equivalent I/O multiplexing function) has
 * returned, and fds related to a particular context are the cause of
 * the select() call being unblocked.
 *
 * A context may not be left unattended (i.e. no calls to
 * paf_process()) by the application for a long duration of time,
 * unless the context's fds aren't becoming active. In other words,
 * the context's fd should always be in the set of fds supplied by the
 * application to select(), until up to the point it is closed with
 * paf_close().
 *
 * paf_process() will never fail, and the return value is only used to
 * inform the application that the context detachment it ordered (via
 * paf_detach()) has completed.
 *
 * @param[in] context The context.
 *
 * @return Returns 0 or PAF_ERR_DETACHED, in case the context has finished the detach process.
 */
int paf_process(struct paf_context *context);

/**
 * Detach the context.
 *
 * This function will initiate the process of detaching the context
 * from any server, attempting to unpublish all services, remove all
 * subscriptions, and finish any outstanding protocol transactions
 * (e.g. unpublish operations that might not yet have finished).
 *
 * To allow the detaching to happen, the application should continue
 * to use select() for wait for the context's fd to become readable,
 * and paf_process() to allow it to make progress.
 *
 * paf_process() will return PAF_ERR_DETACHED when the process has
 * completed (or timed out).
 *
 * Since unpublication is a best-effort exercise, in case the server
 * does not respond within a resonable time, detaching will finish.
 *
 * After paf_detach() has been called, only paf_fd(), paf_process()
 * and paf_close() may be called.
 *
 * @param[in] context The context.
 */
void paf_detach(struct paf_context *context);

/**
 * Close the context.
 *
 * This function will free all resources associated with @ref context.
 *
 * It is legal to call this function, even if the context is still
 * attached (i.e. paf_detach() was not called, or paf_process() has
 * not yet returned PAF_ERR_DETACHED. If it was not detached the
 * services will not be unpublished. Upon client disconnect, such
 * services will be considered orphans, and will be available until
 * their time-to-live (TTL) has expired.
 *
 * @param[in] context The context.
 */
void paf_close(struct paf_context *context);

/**
 * Escape special characters for strings used in filters.
 *
 * This function will copy the input string, escaping any characters
 * which have a special meaning in the subscription filter language
 * (see paf_subscribe()).
 *
 * The input string may contain arbitrary non-NUL characters, and may
 * be of arbitrary length. However, there is a maximum filter size.
 *
 * Since the same escaping mechanism is used for both service property
 * names and string values, paf_filter_escape() may be used for both
 * types.
 * 
 * The string returned is heap-allocated, and it's the caller
 * obligation to use free() to free its memory.
 *
 * This function for creating filter expressions only. It is not
 * needed and should not be used while creating service property
 * string-type values (see paf_value.h) for use in paf_publish().
 *
 * @param[in] s The service property name or string value to be escaped.
 *
 * @return Returns a copy of the string, with special characters escaped.
 */
char *paf_filter_escape(const char *s);

#ifdef __cplusplus
}
#endif
#endif
