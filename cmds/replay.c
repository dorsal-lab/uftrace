#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <inttypes.h>
#include <stdio_ext.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/fstack.h"
#include "utils/list.h"
#include "utils/kernel.h"
#include "utils/field.h"
#include "utils/event.h"
#include "utils/arg.h"

#include "libtraceevent/event-parse.h"


static int column_index;
static int prev_tid = -1;

static LIST_HEAD(output_fields);

#define NO_TIME  (void *)1  /* to suppress duration */

static void print_duration(struct field_data *fd)
{
	struct fstack *fstack = fd->fstack;
	void *arg = fd->arg;
	uint64_t d = 0;

	/* any non-NULL argument suppresses the output */
	if (fstack && arg == NULL)
		d = fstack->total_time;

	print_time_unit(d);
}

static void print_tid(struct field_data *fd)
{
	struct uftrace_task_reader *task = fd->task;
	pr_out("[%6d]", task->tid);
}

static void print_addr(struct field_data *fd)
{
	struct fstack *fstack = fd->fstack;

	/* uftrace records (truncated) 48-bit addresses */
	int width = sizeof(long) == 4 ? 8 : 12;

	if (fstack == NULL)  /* LOST */
		pr_out("%*s", width, "");
	else
		pr_out("%*"PRIx64, width, effective_addr(fstack->addr));
}

static void print_timestamp(struct field_data *fd)
{
	struct uftrace_task_reader *task = fd->task;

	uint64_t  sec = task->timestamp / NSEC_PER_SEC;
	uint64_t nsec = task->timestamp % NSEC_PER_SEC;

	pr_out("%8"PRIu64".%09"PRIu64, sec, nsec);
}

static void print_timedelta(struct field_data *fd)
{
	struct uftrace_task_reader *task = fd->task;
	uint64_t delta = 0;

	if (task->timestamp_last)
		delta = task->timestamp - task->timestamp_last;

	print_time_unit(delta);
}

static void print_elapsed(struct field_data *fd)
{
	struct uftrace_task_reader *task = fd->task;
	uint64_t elapsed = task->timestamp - task->h->time_range.first;

	print_time_unit(elapsed);
}

static void print_task(struct field_data *fd)
{
	struct uftrace_task_reader *task = fd->task;

	pr_out("%*s", 15, task->t->comm);
}

static void print_module(struct field_data *fd)
{
	struct uftrace_task_reader *task = fd->task;
	struct fstack *fstack = fd->fstack;
	uint64_t timestamp = task->timestamp;
	struct uftrace_session *s;
	struct uftrace_mmap *map;
	char *modname = "[unknown]";

	/* for EVENT or LOST record */
	if (fstack == NULL) {
		pr_out("%*s", 16, "");
		return;
	}

	s = find_task_session(&task->h->sessions, task->t, timestamp);
	if (s) {
		map = find_map(&s->symtabs, fstack->addr);
		if (map == MAP_KERNEL)
			modname = "[kernel]";
		else if (map)
			modname = basename(map->libname);
		else if (is_sched_event(fstack->addr))
			modname = "[event]";
	}

	pr_out("%*.*s", 16, 16, modname);
}

static struct display_field field_duration = {
	.id      = REPLAY_F_DURATION,
	.name    = "duration",
	.header  = " DURATION ",
	.length  = 10,
	.print   = print_duration,
	.list    = LIST_HEAD_INIT(field_duration.list),
};

static struct display_field field_tid = {
	.id      = REPLAY_F_TID,
	.name    = "tid",
	.header  = "   TID  ",
	.length  = 8,
	.print   = print_tid,
	.list    = LIST_HEAD_INIT(field_tid.list),
};

static struct display_field field_addr = {
	.id      = REPLAY_F_ADDR,
	.name    = "addr",
#if __SIZEOF_LONG__ == 4
	.header  = " ADDRESS",
	.length  = 8,
#else
	.header  = "   ADDRESS  ",
	.length  = 12,
#endif
	.print   = print_addr,
	.list    = LIST_HEAD_INIT(field_addr.list),
};

static struct display_field field_time = {
	.id      = REPLAY_F_TIMESTAMP,
	.name    = "time",
	.header  = "     TIMESTAMP    ",
	.length  = 18,
	.print   = print_timestamp,
	.list    = LIST_HEAD_INIT(field_time.list),
};

static struct display_field field_delta = {
	.id      = REPLAY_F_TIMEDELTA,
	.name    = "delta",
	.header  = " TIMEDELTA",
	.length  = 10,
	.print   = print_timedelta,
	.list    = LIST_HEAD_INIT(field_delta.list),
};

static struct display_field field_elapsed = {
	.id      = REPLAY_F_ELAPSED,
	.name    = "elapsed",
	.header  = "  ELAPSED ",
	.length  = 10,
	.print   = print_elapsed,
	.list    = LIST_HEAD_INIT(field_elapsed.list),
};

static struct display_field field_task = {
	.id      = REPLAY_F_TASK,
	.name    = "task",
	.header  = "      TASK NAME",
	.length  = 15,
	.print   = print_task,
	.list    = LIST_HEAD_INIT(field_task.list),
};

static struct display_field field_module = {
	.id      = REPLAY_F_MODULE,
	.name    = "module",
	.header  = "     MODULE NAME",
	.length  = 16,
	.print   = print_module,
	.list    = LIST_HEAD_INIT(field_module.list),
};

/* index of this table should be matched to display_field_id */
static struct display_field *field_table[] = {
	&field_duration,
	&field_tid,
	&field_addr,
	&field_time,
	&field_delta,
	&field_elapsed,
	&field_task,
	&field_module,
};

static void print_field(struct uftrace_task_reader *task,
			struct fstack *fstack, void *arg)
{
	struct field_data fd = {
		.task = task,
		.fstack = fstack,
		.arg = arg,
	};

	if (print_field_data(&output_fields, &fd, 1))
		pr_out(" | ");
}

static void setup_default_field(struct list_head *fields, struct opts *opts,
				struct display_field *p_field_table[])
{
	if (opts->range.start > 0 || opts->range.stop > 0) {
		if (opts->range.start_elapsed || opts->range.stop_elapsed)
			add_field(fields, field_table[REPLAY_F_ELAPSED]);
		else
			add_field(fields, field_table[REPLAY_F_TIMESTAMP]);
	}
	add_field(fields, field_table[REPLAY_F_DURATION]);
	add_field(fields, field_table[REPLAY_F_TID]);
}

static int task_column_depth(struct uftrace_task_reader *task, struct opts *opts)
{
	if (!opts->column_view)
		return 0;

	if (task->column_index == -1)
		task->column_index = column_index++;

	return task->column_index * opts->column_offset;
}

static void print_backtrace(struct uftrace_task_reader *task)
{
	struct uftrace_session_link *sessions = &task->h->sessions;
	int i;

	for (i = 0; i < task->stack_count - 1; i++) {
		struct display_field *field;
		struct sym *sym;
		char *name;
		struct fstack *fstack = fstack_get(task, i);
		struct field_data fd = {
			.task = task,
			.fstack = fstack,
		};

		if (fstack == NULL)
			continue;

		sym = task_find_sym_addr(sessions, task,
					 fstack->total_time, fstack->addr);

		pr_out(" ");
		list_for_each_entry(field, &output_fields, list) {
			if (field->id == REPLAY_F_DURATION)
				pr_out("%*s", field->length, "backtrace");
			else
				field->print(&fd);
			pr_out(" ");
		}
		if (!list_empty(&output_fields))
			pr_out("| ");

		name = symbol_getname(sym, fstack->addr);
		pr_gray("/* [%2d] %s */\n", i, name);
		symbol_putname(sym, name);
	}
}

static void print_event(struct uftrace_task_reader *task,
			struct uftrace_record *urec,
			int color)
{
	unsigned evt_id = urec->addr;
	char *evt_name = event_get_name(task->h, evt_id);
	char *evt_data = event_get_data_str(evt_id, task->args.data, true);

	if (evt_id == EVENT_ID_EXTERN_DATA) {
		pr_color(color, "%s: %s", evt_name, (char *)task->args.data);
	}
	else if (evt_id >= EVENT_ID_USER) {
		/* TODO: some events might have arguments */
		pr_color(color, "%s", evt_name);
	}
	else {
		pr_color(color, "%s", evt_name);

		if (evt_data)
			pr_color(color, " (%s)", evt_data);
	}

	free(evt_name);
	free(evt_data);
}

static int print_flat_rstack(struct uftrace_data *handle,
			     struct uftrace_task_reader *task,
			     struct opts *opts)
{
	static int count;
	struct uftrace_record *rstack = task->rstack;
	struct uftrace_session_link *sessions = &task->h->sessions;
	struct sym *sym = NULL;
	char *name;
	struct fstack *fstack;

	sym = task_find_sym(sessions, task, rstack);
	name = symbol_getname(sym, rstack->addr);
	fstack = fstack_get(task, rstack->depth);

	if (fstack == NULL)
		goto out;

	/* skip it if --no-libcall is given */
	if (!opts->libcall && sym && sym->type == ST_PLT_FUNC)
		goto out;

	switch (rstack->type) {
	case UFTRACE_ENTRY:
		pr_out("[%d] ==> %d/%d: ip (%s), time (%"PRIu64")\n",
		       count++, task->tid, rstack->depth,
		       name, rstack->time);
		break;

	case UFTRACE_EXIT:
		pr_out("[%d] <== %d/%d: ip (%s), time (%"PRIu64":%"PRIu64")\n",
		       count++, task->tid, rstack->depth,
		       name, rstack->time, fstack->total_time);
		break;

	case UFTRACE_LOST:
		pr_out("[%d] XXX %d: lost %d records\n",
		       count++, task->tid, (int)rstack->addr);
		break;

	case UFTRACE_EVENT:
		pr_out("[%d] !!! %d: ", count++, task->tid);
		print_event(task, rstack, task->event_color);
		pr_out(" time (%"PRIu64")\n", rstack->time);
		break;
	}
out:
	symbol_putname(sym, name);
	return 0;
}

static void print_task_newline(int current_tid)
{
	if (prev_tid != -1 && current_tid != prev_tid) {
		if (print_empty_field(&output_fields, 1))
			pr_out(" | ");
		pr_out("\n");
	}

	prev_tid = current_tid;
}

void get_argspec_string(struct uftrace_task_reader *task,
			char *args, size_t len,
			enum argspec_string_bits str_mode)
{
	void *data = task->args.data;
	struct list_head *arg_list = task->args.args;

	struct uftrace_session_link *sessions = &task->h->sessions;
	struct uftrace_session *sess =
		find_task_session(sessions, task->t, task->rstack->time);

	struct symtabs symtabs = sess->symtabs;
	struct uftrace_mmap *map = find_map(&sess->symtabs, task->rstack->addr);

	format_argspec_string(args, &symtabs, map, data, arg_list, len, str_mode);
}

static int print_graph_rstack(struct uftrace_data *handle,
			      struct uftrace_task_reader *task,
			      struct opts *opts)
{
	struct uftrace_record *rstack;
	struct uftrace_session_link *sessions = &handle->sessions;
	struct sym *sym = NULL;
	enum argspec_string_bits str_mode = 0;
	char *symname = NULL;
	char args[1024];
	char *libname = "";
	struct uftrace_mmap *map = NULL;
	struct debug_location *loc = NULL;
	char *str_loc = NULL;

	if (task == NULL)
		return 0;

	rstack = task->rstack;
	if (rstack->type == UFTRACE_LOST)
		goto lost;

	sym = task_find_sym(sessions, task, rstack);
	symname = symbol_getname(sym, rstack->addr);

	/* skip it if --no-libcall is given */
	if (!opts->libcall && sym && sym->type == ST_PLT_FUNC)
		goto out;

	if (rstack->type == UFTRACE_ENTRY) {
		if (symname[strlen(symname) - 1] != ')' || rstack->more)
			str_mode |= NEEDS_PAREN;
	}

	task->timestamp_last = task->timestamp;
	task->timestamp = rstack->time;

	if (opts->libname && sym && sym->type == ST_PLT_FUNC) {
		struct uftrace_session *s;

		s = find_task_session(sessions, task->t, rstack->time);
		if (s != NULL) {
			map = find_symbol_map(&s->symtabs, symname);
			if (map != NULL)
				libname = basename(map->libname);
		}
	}

	if (opts->srcline) {
		loc = task_find_loc_addr(sessions, task, rstack->time, rstack->addr);
		if (opts->comment && loc)
			xasprintf(&str_loc, "%s:%d", loc->file->name, loc->line);
	}

	if (rstack->type == UFTRACE_ENTRY) {
		struct uftrace_task_reader *next = NULL;
		struct fstack *fstack;
		int rstack_depth = rstack->depth;
		int depth;
		struct uftrace_trigger tr = {
			.flags = 0,
		};
		int ret;

		ret = fstack_entry(task, rstack, &tr);
		if (ret < 0)
			goto out;

		/* display depth is set in fstack_entry() */
		depth = task->display_depth;

		/* give a new line when tid is changed */
		if (opts->task_newline)
			print_task_newline(task->tid);

		if (tr.flags & TRIGGER_FL_BACKTRACE)
			print_backtrace(task);

		if (tr.flags & TRIGGER_FL_COLOR)
			task->event_color = tr.color;
		else
			task->event_color = DEFAULT_EVENT_COLOR;

		depth += task_column_depth(task, opts);

		if (rstack->more && opts->show_args)
			str_mode |= HAS_MORE;
		get_argspec_string(task, args, sizeof(args), str_mode);

		fstack = fstack_get(task, task->stack_count - 1);

		if (!opts->no_merge)
			next = fstack_skip(handle, task, rstack_depth, opts);

		if (task == next &&
		    next->rstack->depth == rstack_depth &&
		    next->rstack->type == UFTRACE_EXIT) {
			char retval[1024];

			/* leaf function - also consume return record */
			fstack_consume(handle, next);

			str_mode = IS_RETVAL | NEEDS_SEMI_COLON;
			if (next->rstack->more && opts->show_args) {
				str_mode |= HAS_MORE;
				str_mode |= NEEDS_ASSIGNMENT;
			}
			get_argspec_string(task, retval, sizeof(retval), str_mode);

			print_field(task, fstack, NULL);
			pr_out("%*s", depth * 2, "");
			if (tr.flags & TRIGGER_FL_COLOR) {
				pr_color(tr.color, "%s", symname);
				if (*libname)
					pr_color(tr.color, "@%s", libname);
				pr_out("%s%s", args, retval);
			}
			else {
				pr_out("%s%s%s%s%s", symname,
				       *libname ? "@" : "",
				       libname, args, retval);
			}
			if (str_loc)
				pr_gray(" /* %s */", str_loc);
			pr_out("\n");

			/* fstack_update() is not needed here */

			fstack_exit(task);
		}
		else {
			/* function entry */
			print_field(task, fstack, NO_TIME);
			pr_out("%*s", depth * 2, "");
			if (tr.flags & TRIGGER_FL_COLOR) {
				pr_color(tr.color, "%s", symname);
				if (*libname)
					pr_color(tr.color, "@%s", libname);
				pr_out("%s {", args);
			}
			else {
				pr_out("%s%s%s%s {", symname,
				       *libname ? "@" : "", libname, args);
			}
			if (str_loc)
				pr_gray(" /* %s */", str_loc);
			pr_out("\n");

			fstack_update(UFTRACE_ENTRY, task, fstack);
		}
	}
	else if (rstack->type == UFTRACE_EXIT) {
		struct fstack *fstack;

		/* function exit */
		fstack = fstack_get(task, task->stack_count);

		if (fstack_enabled && fstack != NULL &&
		    !(fstack->flags & FSTACK_FL_NORECORD)) {
			int depth = fstack_update(UFTRACE_EXIT, task, fstack);
			char *retval = args;

			depth += task_column_depth(task, opts);

			str_mode = IS_RETVAL;
			if (rstack->more && opts->show_args) {
				str_mode |= HAS_MORE;
				str_mode |= NEEDS_ASSIGNMENT;
				str_mode |= NEEDS_SEMI_COLON;
			}
			get_argspec_string(task, retval, sizeof(args), str_mode);

			/* give a new line when tid is changed */
			if (opts->task_newline)
				print_task_newline(task->tid);

			print_field(task, fstack, NULL);
			pr_out("%*s}%s", depth * 2, "", retval);
			if (opts->comment) {
				pr_gray(" /* %s%s%s */", symname,
					*libname ? "@" : "", libname);
			}
			pr_out("\n");
		}

		fstack_exit(task);
	}
	else if (rstack->type == UFTRACE_LOST) {
		int depth, losts;
lost:
		depth = task->display_depth + 1;
		losts = (int)rstack->addr;

		/* skip kernel lost messages outside of user functions */
		if (opts->kernel_skip_out && task->user_stack_count == 0)
			return 0;

		/* give a new line when tid is changed */
		if (opts->task_newline)
			print_task_newline(task->tid);

		print_field(task, NULL, NO_TIME);

		if (losts > 0)
			pr_red("%*s/* LOST %d records!! */\n",
			       depth * 2, "", losts);
		else /* kernel sometimes have unknown count */
			pr_red("%*s/* LOST some records!! */\n",
			       depth * 2, "");
		free(str_loc);
		return 0;
	}
	else if (rstack->type == UFTRACE_EVENT) {
		int depth;
		struct fstack *fstack;
		struct uftrace_task_reader *next = NULL;
		struct uftrace_record rec = *rstack;
		uint64_t evt_id = rstack->addr;

		depth = task->display_depth;

		if (!fstack_check_filter(task))
			goto out;

		/* give a new line when tid is changed */
		if (opts->task_newline)
			print_task_newline(task->tid);

		depth += task_column_depth(task, opts);

		/*
		 * try to merge a subsequent sched-in event:
		 * it might overwrite rstack - use (saved) rec for printing.
		 */
		if (evt_id == EVENT_ID_PERF_SCHED_OUT && !opts->no_merge)
			next = fstack_skip(handle, task, 0, opts);

		if (task == next &&
		    next->rstack->addr == EVENT_ID_PERF_SCHED_IN) {
			/* consume the matching sched-in record */
			fstack_consume(handle, next);

			rec.addr = sched_sym.addr;
			evt_id = EVENT_ID_PERF_SCHED_IN;
		}

		/* show external data regardless of display depth */
		if (evt_id == EVENT_ID_EXTERN_DATA)
			depth = 0;

		/* for sched-in to show schedule duration */
		fstack = fstack_get(task, task->stack_count);

		if (fstack_enabled && fstack != NULL &&
		    !(fstack->flags & FSTACK_FL_NORECORD)) {
			if (evt_id == EVENT_ID_PERF_SCHED_IN &&
			    fstack->total_time)
				print_field(task, fstack, NULL);
			else
				print_field(task, NULL, NO_TIME);

			pr_color(task->event_color, "%*s/* ", depth * 2, "");
			print_event(task, &rec, task->event_color);
			pr_color(task->event_color, " */\n");
		}
	}
out:
	symbol_putname(sym, symname);
	free(str_loc);
	return 0;
}

static void print_warning(struct uftrace_task_reader *task)
{
	if (print_empty_field(&output_fields, 1))
		pr_out(" | ");
	pr_red(" %*s/* inverted time: broken data? */\n",
	       (task->display_depth + 1) * 2, "");
}

static bool skip_sys_exit(struct opts *opts, struct uftrace_task_reader *task)
{
	struct sym *sym;
	struct fstack *fstack;

	fstack = fstack_get(task, 0);
	if (fstack == NULL)
		return true;

	/* skip 'sys_exit[_group] at last for kernel tracing */
	if (!has_kernel_data(task->h->kernel) || task->user_stack_count != 0)
		return false;

	sym = find_symtabs(&task->h->sessions.first->symtabs, fstack->addr);
	if (sym == NULL)
		return false;

	/* Linux 4.17 added __x64_sys_exit, __ia32_sys_exit and so on */
	if (strstr(sym->name, "sys_exit"))
		return true;
	if (!strcmp(sym->name, "do_syscall_64"))
		return true;

	return false;
}

static void print_remaining_stack(struct opts *opts,
				  struct uftrace_data *handle)
{
	int i, k;
	int total = 0;
	struct uftrace_session_link *sessions = &handle->sessions;

	for (i = 0; i < handle->nr_tasks; i++) {
		struct uftrace_task_reader *task = &handle->tasks[i];
		int zero_count = 0;

		if (skip_sys_exit(opts, task))
			continue;

		if (task->stack_count == 1) {
			struct fstack *fstack = fstack_get(task, 0);

			/* ignore if it only has a schedule event */
			if (fstack && fstack->addr == EVENT_ID_PERF_SCHED_OUT)
				continue;
		}

		/* sometimes it has many 0 entries in the fstack. ignore them */
		for (k = 0; k < task->stack_count; k++) {
			struct fstack *fstack;

			fstack = fstack_get(task, k);
			if (fstack != NULL && fstack->addr != 0)
				break;
			zero_count++;
		}

		total += task->stack_count - zero_count;
	}

	if (total == 0)
		return;

	pr_out("\nuftrace stopped tracing with remaining functions");
	pr_out("\n================================================\n");

	for (i = 0; i < handle->nr_tasks; i++) {
		struct uftrace_task_reader *task = &handle->tasks[i];
		struct fstack *fstack;
		int zero_count = 0;

		if (task->stack_count == 0)
			continue;

		if (task->stack_count == 1) {
			fstack = fstack_get(task, 0);

			/* skip if it only has a schedule event */
			if (fstack && fstack->addr == EVENT_ID_PERF_SCHED_OUT)
				continue;
		}

		for (k = 0; k < task->stack_count; k++) {
			fstack = fstack_get(task, k);
			if (fstack != NULL && fstack->addr != 0)
				break;
			zero_count++;
		}

		if (zero_count == task->stack_count)
			continue;

		if (skip_sys_exit(opts, task))
			continue;

		pr_out("task: %d\n", task->tid);

		while (task->stack_count-- > 0) {
			uint64_t time;
			uint64_t ip;
			struct sym *sym;
			char *symname;

			fstack = fstack_get(task, task->stack_count);
			if (fstack == NULL)
				continue;

			time = fstack->total_time;
			ip = fstack->addr;
			sym = task_find_sym_addr(sessions, task, time, ip);
			symname = symbol_getname(sym, ip);

			pr_out("[%d] %s\n", task->stack_count - zero_count, symname);

			symbol_putname(sym, symname);

			if (task->stack_count == zero_count)
				break;
		}
		pr_out("\n");
	}
}

int command_replay(int argc, char *argv[], struct opts *opts)
{
	int ret;
	uint64_t prev_time = 0;
	struct uftrace_data handle;
	struct uftrace_task_reader *task;

	__fsetlocking(outfp, FSETLOCKING_BYCALLER);
	__fsetlocking(logfp, FSETLOCKING_BYCALLER);

	ret = open_data_file(opts, &handle);
	if (ret < 0) {
		pr_warn("cannot open record data: %s: %m\n", opts->dirname);
		return -1;
	}

	fstack_setup_filters(opts, &handle);
	setup_field(&output_fields, opts, &setup_default_field,
		    field_table, ARRAY_SIZE(field_table));

	if (format_mode == FORMAT_HTML)
		pr_out(HTML_HEADER);

	if (!opts->flat && peek_rstack(&handle, &task) == 0)
		print_header(&output_fields, "#", "FUNCTION", 1, false);
	if (!list_empty(&output_fields)) {
		if (opts->srcline)
			pr_gray(" [SOURCE]");
		pr_out("\n");
	}

	while (read_rstack(&handle, &task) == 0 && !uftrace_done) {
		struct uftrace_record *rstack = task->rstack;
		uint64_t curr_time = rstack->time;

		if (!fstack_check_opts(task, opts))
			continue;

		/*
		 * data sanity check: timestamp should be ordered.
		 * But print_graph_rstack() may change task->rstack
		 * during fstack_skip().  So check the timestamp here.
		 */
		if (curr_time) {
			if (prev_time > curr_time)
				print_warning(task);
			prev_time = rstack->time;
		}

		if (opts->flat)
			ret = print_flat_rstack(&handle, task, opts);
		else
			ret = print_graph_rstack(&handle, task, opts);

		if (ret)
			break;
	}

	print_remaining_stack(opts, &handle);

	if (format_mode == FORMAT_HTML)
		pr_out(HTML_FOOTER);

	close_data_file(opts, &handle);

	return ret;
}
