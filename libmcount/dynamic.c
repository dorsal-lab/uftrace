/*
 * INSTRUMENTED CODE LAYOUT
 *
 * Func offset | Instrumented code
 * --------------------------------
 * 	   0x0 | Call Trampoline
 * 	   0x6 | nop
 * 	   0x7 | nop
 *
 * we must use starting address of function when
 * -. store original code to hashmap
 * -. find original code from hashmap
 * -. unpatch function
 */
#include <string.h>
#include <stdint.h>
#include <link.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "libmcount/dynamic.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/filter.h"
#include "utils/rbtree.h"
#include "utils/list.h"
#include "utils/hashmap.h"

static struct mcount_dynamic_info *mdinfo;
static struct mcount_dynamic_stats {
	int total;
	int failed;
	int skipped;
	int nomatch;
	int unpatch;
} stats;

#define PAGE_SIZE   4096
#define CODE_CHUNK  (PAGE_SIZE * 8)

struct code_page {
	struct list_head	list;
	void			*page;
	int			pos;
	bool			frozen;
};

static LIST_HEAD(code_pages);

static struct Hashmap *code_hmap;

/* minimum function size for dynamic update */
static unsigned min_size;

/* disassembly engine for dynamic code patch (for capstone) */
static struct mcount_disasm_engine disasm;

static struct mcount_orig_insn *create_code(struct Hashmap *map,
					    unsigned long addr)
{
	struct mcount_orig_insn *entry;

	entry = xmalloc(sizeof *entry);
	entry->addr = addr;
	if (hashmap_put(code_hmap, (void *)entry->addr, entry) == NULL)
		pr_err("code map allocation failed");
	return entry;
}

static struct mcount_orig_insn *lookup_code(struct Hashmap *map,
					    unsigned long addr)
{
	struct mcount_orig_insn *entry;

	entry = hashmap_get(code_hmap, (void *)addr);
	return entry;
}

static struct code_page *alloc_codepage(void)
{
	struct code_page *cp;

	cp = xzalloc(sizeof(*cp));
	cp->page = mmap(NULL, CODE_CHUNK, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (cp->page == MAP_FAILED)
		pr_err("mmap code page failed");

	list_add_tail(&cp->list, &code_pages);
	return cp;
}

void mcount_save_code(struct mcount_disasm_info *info, unsigned call_size,
		      void *jmp_insn, unsigned jmp_size)
{
	struct code_page *cp = NULL;
	struct mcount_orig_insn *orig;
	int patch_size;

	if (unlikely(info->modified)) {
		/* it needs to save original instructions as well */
		int orig_size = ALIGN(info->orig_size, 16);
		int copy_size = ALIGN(info->copy_size + jmp_size, 16);
		int table_size = mcount_arch_branch_table_size(info);

		patch_size = ALIGN(copy_size + orig_size + table_size, 32);
	}
	else {
		patch_size = ALIGN(info->copy_size + jmp_size, 32);
	}

	if (!list_empty(&code_pages))
		cp = list_last_entry(&code_pages, struct code_page, list);

	if (cp == NULL || (cp->pos + patch_size > CODE_CHUNK)) {
		cp = alloc_codepage();
	}

	orig = create_code(code_hmap, info->addr + call_size);

	/*
	 * if dynamic patch has been processed before, cp be frozen by
	 * calling freeze_code. so, when reaching here from the
	 * mcount_handle_dlopen, cp unwriteable.
	 */
	if (cp->frozen) {
		/* [Caution]
		 * even if a little memory loss occurs, it can be dangerous
		 * that to re-assigned write and execute permission to exist
		 * codepage, so be sure to allocate new memory.
		 */
		cp = alloc_codepage();
	}

	orig->insn = cp->page + cp->pos;
	orig->orig = orig->insn;
	orig->orig_size = info->orig_size;
	orig->insn_size = info->copy_size + jmp_size;

	if (info->modified) {
		/* save original instructions before modification */
		orig->orig = orig->insn + patch_size - ALIGN(info->orig_size, 16);
		memcpy(orig->orig, (void *)info->addr, info->orig_size);

		mcount_arch_patch_branch(info, orig);
	}

	memcpy(orig->insn, info->insns, info->copy_size);
	memcpy(orig->insn + info->copy_size, jmp_insn, jmp_size);

	cp->pos += patch_size;
}

void mcount_freeze_code(void)
{
	struct code_page *cp;

	list_for_each_entry(cp, &code_pages, list) {
		if (cp->frozen)
			continue;

		if (mprotect(cp->page, CODE_CHUNK, PROT_READ | PROT_EXEC) < 0)
			pr_err("mprotect to freeze code page failed");
		cp->frozen = true;
	}
}

void *mcount_find_code(unsigned long addr)
{
	struct mcount_orig_insn *orig;

	orig = lookup_code(code_hmap, addr);
	if (orig == NULL)
		return NULL;

	return orig->insn;
}

struct mcount_orig_insn * mcount_find_insn(unsigned long addr)
{
	return lookup_code(code_hmap, addr);
}

static bool release_code(void *key, void *value, void *ctx)
{
	hashmap_remove(code_hmap, key);
	free(value);
	return true;
}

/* not actually called for safety reason */
void mcount_release_code(void)
{
	hashmap_for_each(code_hmap, release_code, NULL);
	hashmap_free(code_hmap);

	while (!list_empty(&code_pages)) {
		struct code_page *cp;

		cp = list_first_entry(&code_pages, struct code_page, list);
		list_del(&cp->list);
		munmap(cp->page, CODE_CHUNK);
		free(cp);
	}
}

/* dummy functions (will be overridden by arch-specific code) */
__weak int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	return -1;
}

__weak void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
}

__weak int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			     struct mcount_disasm_engine *disasm,
			     unsigned min_size)
{
	return -1;
}

__weak int mcount_unpatch_func(struct mcount_dynamic_info *mdi, struct sym *sym,
			       struct mcount_disasm_engine *disasm)
{
	return -1;
}

__weak void mcount_arch_find_module(struct mcount_dynamic_info *mdi,
				    struct symtab *symtab)
{
}

__weak void mcount_arch_dynamic_recover(struct mcount_dynamic_info *mdi,
					struct mcount_disasm_engine *disasm)
{
}

__weak void mcount_disasm_init(struct mcount_disasm_engine *disasm)
{
}

__weak void mcount_disasm_finish(struct mcount_disasm_engine *disasm)
{
}

__weak int mcount_arch_branch_table_size(struct mcount_disasm_info *info)
{
	return 0;
}

__weak void mcount_arch_patch_branch(struct mcount_disasm_info *info,
				     struct mcount_orig_insn *orig)
{
}

struct find_module_data {
	struct symtabs *symtabs;
	bool needs_modules;
	bool skip_first;
};

static struct mcount_dynamic_info *create_mdi(struct dl_phdr_info *info)
{
	struct mcount_dynamic_info *mdi;
	bool base_addr_set = false;
	unsigned i;

	mdi = xzalloc(sizeof(*mdi));

	for (i = 0; i < info->dlpi_phnum; i++) {
		if (info->dlpi_phdr[i].p_type != PT_LOAD)
			continue;

		if (!base_addr_set) {
			mdi->base_addr = info->dlpi_phdr[i].p_vaddr;
			base_addr_set = true;
		}

		if (!(info->dlpi_phdr[i].p_flags & PF_X))
			continue;

		/* find address and size of code segment */
		mdi->text_addr = info->dlpi_phdr[i].p_vaddr;
		mdi->text_size = info->dlpi_phdr[i].p_memsz;
		break;
	}
	mdi->base_addr += info->dlpi_addr;
	mdi->text_addr += info->dlpi_addr;
	INIT_LIST_HEAD(&mdi->bad_syms);

	return mdi;
}

/* callback for dl_iterate_phdr() */
static int find_dynamic_module(struct dl_phdr_info *info, size_t sz, void *data)
{
	struct mcount_dynamic_info *mdi;
	struct find_module_data *fmd = data;
	struct symtabs *symtabs = fmd->symtabs;
	struct uftrace_mmap *map;

	if (fmd->skip_first) {
		fmd->skip_first = false;
		return !fmd->needs_modules;
	}

	mdi = create_mdi(info);
	map = find_map(symtabs, mdi->base_addr);
	if (map && map->mod) {
		mdi->map = map;
		mcount_arch_find_module(mdi, &map->mod->symtab);

		mdi->next = mdinfo;
		mdinfo = mdi;
	}
	else {
		free(mdi);
	}

	return !fmd->needs_modules;
}

static void load_modules_dynamic_info(struct symtabs *symtabs, bool needs_modules)
{
	static enum {
		NONE_LOADED,
		MAIN_BINARY_LOADED,
		ALL_MODULES_LOADED,
	} loaded_module = NONE_LOADED;

	struct find_module_data callback_data = {
		.symtabs = symtabs,
		.needs_modules = needs_modules,
		.skip_first = (loaded_module == MAIN_BINARY_LOADED),
	};

	switch (loaded_module) {
	case NONE_LOADED:
		dl_iterate_phdr(find_dynamic_module, &callback_data);
		loaded_module = needs_modules ? ALL_MODULES_LOADED : MAIN_BINARY_LOADED;
		break;

	case MAIN_BINARY_LOADED:
		if (!needs_modules) {
			return;
		}

		dl_iterate_phdr(find_dynamic_module, &callback_data);
		loaded_module = ALL_MODULES_LOADED;
		break;

	case ALL_MODULES_LOADED:
		return;
	}
}

struct mcount_dynamic_info *setup_trampoline(struct uftrace_mmap *map)
{
	struct mcount_dynamic_info *mdi;

	for (mdi = mdinfo; mdi != NULL; mdi = mdi->next) {
		if (map == mdi->map)
			break;
	}

	if (mdi != NULL && mdi->trampoline == 0) {
		if (mcount_setup_trampoline(mdi) < 0)
			mdi = NULL;
	}

	return mdi;
}

static LIST_HEAD(patch_patterns);
static LIST_HEAD(unpatch_patterns);

struct patt_list {
	struct list_head list;
	struct uftrace_pattern patt;
	char *module;
	bool positive;
};

static bool match_pattern_module(char *pathname, struct list_head *patterns)
{
	struct patt_list *pl;
	bool ret = false;
	char *libname = basename(pathname);
	char *soname = get_soname(pathname);

	list_for_each_entry(pl, patterns, list) {
		if (!strncmp(libname, pl->module, strlen(pl->module))) {
			ret = true;
			break;
		}

		if (soname && !strncmp(soname, pl->module, strlen(pl->module))) {
			ret = true;
			break;
		}
	}

	free(soname);
	return ret;
}

/* FIXME arguments order: patterns first */
static bool match_pattern_list(struct uftrace_mmap *map, char *soname,
			       char *sym_name, struct list_head *patterns)
{
	struct patt_list *pl;
	bool ret = false;
	char *libname = basename(map->libname);

	list_for_each_entry(pl, patterns, list) {
		int len = strlen(pl->module);

		if (strncmp(libname, pl->module, len) &&
		    (!soname || strncmp(soname, pl->module, len)))
			continue;

		if (match_filter_pattern(&pl->patt, sym_name))
			ret = pl->positive;
	}

	return ret;
}

static void parse_pattern_string(char *funcs, char *def_mod,
			        enum uftrace_pattern_type ptype,
				struct list_head *patterns,
				bool *all_negative, bool invert)
{
	struct strv funcs_v = STRV_INIT;
	char *name;
	int j;
	struct patt_list *pl;

	strv_split(&funcs_v, funcs, ";");

	strv_for_each(&funcs_v, name, j) {
		char *delim;

		pl = xzalloc(sizeof(*pl));

		if (name[0] == '!') {
			if (invert) {
				free(pl);
				continue;
			}
			else {
				name++;
				pl->positive = false;
			}
		}
		else {
			pl->positive = !invert;
			*all_negative = false;
		}

		delim = strchr(name, '@');
		if (delim == NULL) {
			pl->module = xstrdup(def_mod);
		}
		else {
			*delim = '\0';
			pl->module = xstrdup(++delim);
		}

		init_filter_pattern(ptype, &pl->patt, name);
		list_add_tail(&pl->list, patterns); /* FIXME smart insertion */
	}

	strv_free(&funcs_v);
}

static void fill_pattern_list(struct list_head *patterns, char *funcs,
			char *exceptions, char *def_mod,
			enum uftrace_pattern_type ptype)
{
	bool all_negative = true;

	parse_pattern_string(funcs, def_mod, ptype, patterns, &all_negative, false);

	/* prepend match-all pattern, if all patterns are negative */
	if (all_negative) {
		struct patt_list *pl;
		pl = xzalloc(sizeof(*pl));
		pl->positive = true;
		pl->module = xstrdup(def_mod);

		if (ptype == PATT_REGEX)
			init_filter_pattern(ptype, &pl->patt, ".");
		else
			init_filter_pattern(PATT_GLOB, &pl->patt, "*");

		list_add(&pl->list, patterns);

		parse_pattern_string(exceptions, def_mod, ptype, patterns, &all_negative, true);
	}
}

static void release_pattern_list(struct list_head *patterns)
{
	struct patt_list *pl, *tmp;

	list_for_each_entry_safe(pl, tmp, patterns, list) {
		list_del(&pl->list);
		free_filter_pattern(&pl->patt);
		free(pl->module);
		free(pl);
	}
}

static bool skip_sym(struct sym *sym, struct mcount_dynamic_info *mdi,
		     struct uftrace_mmap *map, char *soname,
		     struct list_head *patterns)
{
	/* skip special startup (csu) functions */
	const char *csu_skip_syms[] = {
		"_start",
		"__libc_csu_init",
		"__libc_csu_fini",
	};
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(csu_skip_syms); i++) {
		if (!strcmp(sym->name, csu_skip_syms[i]))
			return true;
	}

	if (sym->type != ST_LOCAL_FUNC &&
	    sym->type != ST_GLOBAL_FUNC &&
	    sym->type != ST_WEAK_FUNC)
		return true;

	return false;
}

static void mcount_patch_func_with_stats(struct mcount_dynamic_info *mdi,
					 struct sym *sym)
{
	switch (mcount_patch_func(mdi, sym, &disasm, min_size)) {
	case INSTRUMENT_FAILED:
		stats.failed++;
		break;
	case INSTRUMENT_SKIPPED:
		stats.skipped++;
		break;
	case INSTRUMENT_SUCCESS:
	default:
		break;
	}
	stats.total++;
}

static void mcount_update_func(struct mcount_dynamic_info *mdi,
			struct uftrace_mmap *map, struct sym *sym, char *soname,
			bool *found)
{
	if (match_pattern_list(map, soname, sym->name, &patch_patterns)) {
		if (found)
			*found = true;
		mcount_patch_func_with_stats(mdi, sym);
	}
	else if (match_pattern_list(map, soname, sym->name, &unpatch_patterns)) {
		if (mcount_unpatch_func(mdi, sym, &disasm) == INSTRUMENT_SUCCESS)
			stats.unpatch++;
	}
}

static void update_patchable_func_matched(struct mcount_dynamic_info *mdi,
					 struct uftrace_mmap *map)
{
	struct symtab *symtab;
	unsigned long *patchable_loc = mdi->patch_target;
	unsigned i;
	struct sym *sym;
	char namebuf[BUFSIZ];
	struct sym fake_sym = {
		.size = UINT_MAX,
		.name = namebuf,
	};
	char *soname = get_soname(map->libname);

	symtab = &map->mod->symtab;

	/*
	 * If __patchable_function_entries is found, then apply patching
	 * only to the target addresses found at the section.
	 */
	for (i = 0; i < mdi->nr_patch_target; i++) {
		uint64_t rel_addr = patchable_loc[i];
		struct sym *searched_sym = find_sym(symtab, rel_addr);

		if (searched_sym == NULL) {
			sym = &fake_sym;
			sym->addr = rel_addr;
			snprintf(sym->name, sizeof(namebuf), "<%lx>", patchable_loc[i]);
		}
		else {
			sym = searched_sym;
			if (skip_sym(sym, mdi, map, soname, &patch_patterns))
				continue;
		}

		mcount_update_func(mdi, map, sym, soname, NULL);
	}

	free(soname);
}

static void update_normal_func_matched(struct mcount_dynamic_info *mdi,
				      struct uftrace_mmap *map)
{
	struct symtab *symtab;
	unsigned i;
	struct sym *sym;
	bool found = false;
	char *soname = get_soname(map->libname);

	symtab = &map->mod->symtab;

	for (i = 0; i < symtab->nr_sym; i++) {
		sym = &symtab->sym[i];

		if (skip_sym(sym, mdi, map, soname, &patch_patterns))
			continue;

		mcount_update_func(mdi, map, sym, soname, &found);
	}

	if (!found)
		stats.nomatch++;

	free(soname);
}

static void update_func_matched(struct mcount_dynamic_info *mdi,
			       struct uftrace_mmap *map)
{
	/*
	 * In some cases, the __patchable_function_entries section can be
	 * removed.  For example, -Wl,--gc-sections strips this section.
	 * In this case, we try patching in patch_normal_func_matched() by
	 * looping over all the symbols available and check if the function
	 * begins with NOP patterns for patchable function entry.
	 */
	if (mdi->type == DYNAMIC_PATCHABLE)
		update_patchable_func_matched(mdi, map);
	else
		update_normal_func_matched(mdi, map);
}

static int do_dynamic_update(struct symtabs *symtabs, char *patch_funcs,
			char *unpatch_funcs, enum uftrace_pattern_type ptype)
{
	struct uftrace_mmap *map;
	char *def_mod;

	if (!patch_funcs && !unpatch_funcs)
		return 0;
	if (!patch_funcs)
		patch_funcs = "";
	if (!unpatch_funcs)
		unpatch_funcs = "";

	def_mod = basename(symtabs->exec_map->libname);
	fill_pattern_list(&patch_patterns, patch_funcs, unpatch_funcs, def_mod, ptype);
	fill_pattern_list(&unpatch_patterns, unpatch_funcs, patch_funcs, def_mod, ptype);

	for_each_map(symtabs, map) {
		struct mcount_dynamic_info *mdi;

		/* TODO: filter out unsuppported libs */
		mdi = setup_trampoline(map);
		if (mdi == NULL)
			continue;

		update_func_matched(mdi, map);
	}

	if (stats.failed + stats.skipped + stats.nomatch == 0) {
		pr_dbg("patched all (%d) functions in '%s'\n",
		       stats.total, basename(symtabs->filename));
	}

	release_pattern_list(&patch_patterns);
	release_pattern_list(&unpatch_patterns);

	return 0;
}

static void freeze_dynamic_update(void)
{
	struct mcount_dynamic_info *mdi, *tmp;

	mdi = mdinfo;
	while (mdi) {
		tmp = mdi->next;

		mcount_arch_dynamic_recover(mdi, &disasm);
		mcount_cleanup_trampoline(mdi);
		free(mdi);

		mdi = tmp;
	}

	mcount_freeze_code();
}

/* do not use floating-point in libmcount */
static int calc_percent(int n, int total, int *rem)
{
	int quot = 100 * n / total;

	*rem = (100 * n - quot * total) * 100 / total;
	return quot;
}

int mcount_dynamic_init(struct symtabs *symtabs, char *patch_str,
			char *unpatch_str)
{
	char *size_filter = NULL;
	int hash_size;

	mcount_disasm_init(&disasm);

	hash_size = symtabs->exec_map->mod->symtab.nr_sym * 3 / 4;
	code_hmap = hashmap_create(hash_size, hashmap_ptr_hash, hashmap_ptr_equals);
	if (code_hmap == NULL) {
		return -1;
	}

	if (patch_str) {	/* FIXME not pretty */
		size_filter = getenv("UFTRACE_PATCH_SIZE");
	}
	else if (unpatch_str) {
		size_filter = getenv("UFTRACE_UNPATCH_SIZE");
	}

	if (size_filter != NULL)
		min_size = strtoul(size_filter, NULL, 0);

	return 0;
}

int mcount_dynamic_update(struct symtabs *symtabs, char *patch_funcs,
			  char *unpatch_funcs, enum uftrace_pattern_type ptype)
{
	int ret = 0;
	bool needs_modules = (patch_funcs && !!strchr(patch_funcs, '@')) ||
		(unpatch_funcs && !!strchr(unpatch_funcs, '@'));

	mcount_disasm_init(&disasm);
	load_modules_dynamic_info(symtabs, needs_modules);

	ret = do_dynamic_update(symtabs, patch_funcs, unpatch_funcs, ptype);

	if (stats.total && stats.failed) {
		int success = stats.total - stats.failed - stats.skipped;
		int r, q;

		pr_dbg("dynamic patch stats for '%s'\n",
		       basename(symtabs->filename));
		pr_dbg("   total: %8d\n", stats.total);
		q = calc_percent(success, stats.total, &r);
		pr_dbg(" patched: %8d (%2d.%02d%%)\n", success, q, r);
		q = calc_percent(stats.failed, stats.total, &r);
		pr_dbg("  failed: %8d (%2d.%02d%%)\n", stats.failed, q, r);
		q = calc_percent(stats.skipped, stats.total, &r);
		pr_dbg(" skipped: %8d (%2d.%02d%%)\n", stats.skipped, q, r);
		pr_dbg("no match: %8d\n", stats.nomatch);
	}

	freeze_dynamic_update();
	return ret;
}

void mcount_dynamic_dlopen(struct symtabs *symtabs, struct dl_phdr_info *info,
			   char *pathname)
{
	struct mcount_dynamic_info *mdi;
	struct uftrace_mmap *map;

	if (!match_pattern_module(pathname, &patch_patterns))
		return;

	mdi = create_mdi(info);

	map = xmalloc(sizeof(*map) + strlen(pathname) + 1);
	map->start = info->dlpi_addr;
	map->end = map->start + mdi->text_size;
	map->len = strlen(pathname);

	strcpy(map->libname, pathname);
	mcount_memcpy1(map->prot, "r-xp", 4);
	read_build_id(pathname, map->build_id, sizeof(map->build_id));

	map->next = symtabs->maps;
	symtabs->maps = map;
	mdi->map = map;

	map->mod = load_module_symtab(symtabs, map->libname, map->build_id);
	mcount_arch_find_module(mdi, &map->mod->symtab);

	if (mcount_setup_trampoline(mdi) < 0) {
		pr_dbg("setup trampoline to %s failed\n", map->libname);
		free(mdi);
		return;
	}

	update_func_matched(mdi, map);

	mcount_arch_dynamic_recover(mdi, &disasm);
	mcount_cleanup_trampoline(mdi);
	free(mdi);

	mcount_freeze_code();

	release_pattern_list(&patch_patterns);
	release_pattern_list(&unpatch_patterns);
}

void mcount_dynamic_finish(void)
{
	mcount_disasm_finish(&disasm);
}

struct dynamic_bad_symbol * mcount_find_badsym(struct mcount_dynamic_info *mdi,
					       unsigned long addr)
{
	struct sym *sym;
	struct dynamic_bad_symbol *badsym;

	sym = find_sym(&mdi->map->mod->symtab, addr - mdi->map->start);
	if (sym == NULL)
		return NULL;

	list_for_each_entry(badsym, &mdi->bad_syms, list) {
		if (badsym->sym == sym)
			return badsym;
	}

	return NULL;
}

bool mcount_add_badsym(struct mcount_dynamic_info *mdi, unsigned long callsite,
		       unsigned long target)
{
	struct sym *sym;
	struct dynamic_bad_symbol *badsym;

	if (mcount_find_badsym(mdi, target))
		return true;

	sym = find_sym(&mdi->map->mod->symtab, target - mdi->map->start);
	if (sym == NULL)
		return true;

	/* only care about jumps to the middle of a function */
	if (sym->addr + mdi->map->start == target)
		return false;

	pr_dbg2("bad jump: %s:%lx to %lx\n", sym ? sym->name : "<unknown>",
		callsite - mdi->map->start, target - mdi->map->start);

	badsym = xmalloc(sizeof(*badsym));
	badsym->sym = sym;
	badsym->reverted = false;

	list_add_tail(&badsym->list, &mdi->bad_syms);
	return true;
}

void mcount_free_badsym(struct mcount_dynamic_info *mdi)
{
	struct dynamic_bad_symbol *badsym, *tmp;

	list_for_each_entry_safe(badsym, tmp, &mdi->bad_syms, list) {
		list_del(&badsym->list);
		free(badsym);
	}
}

#ifdef UNIT_TEST
TEST_CASE(dynamic_find_code)
{
	struct mcount_disasm_info info1 = {
		.addr = 0x1000,
		.insns = { 0xaa, 0xbb, 0xcc, 0xdd, },
		.orig_size = 4,
		.copy_size = 4,
	};
	struct mcount_disasm_info info2 = {
		.addr = 0x2000,
		.insns = { 0xf1, 0xf2, 0xcc, 0xdd, },
		.orig_size = 2,
		.copy_size = 4,
	};
	uint8_t jmp_insn[] = { 0xcc };
	uint8_t *insn;

	pr_dbg("create hash map to search code\n");
	code_hmap = hashmap_create(4, hashmap_ptr_hash, hashmap_ptr_equals);

	pr_dbg("save fake code to the hash\n");
	mcount_save_code(&info1, 0, jmp_insn, sizeof(jmp_insn));
	mcount_save_code(&info2, 0, jmp_insn, sizeof(jmp_insn));

	pr_dbg("freeze the code page\n");
	mcount_freeze_code();

	pr_dbg("finding the first code\n");
	insn = mcount_find_code(info1.addr);
	TEST_NE(insn, NULL);
	TEST_MEMEQ(insn, info1.insns, info1.orig_size);

	pr_dbg("finding the second code\n");
	insn = mcount_find_code(info2.addr);
	TEST_NE(insn, NULL);
	TEST_MEMEQ(insn, info2.insns, info2.orig_size);

	pr_dbg("release the code page and hash\n");
	mcount_release_code();
	return TEST_OK;
}

TEST_CASE(dynamic_pattern_list)
{
	struct uftrace_mmap *main_map, *other_map;

	main_map = xzalloc(sizeof(*main_map) + 16);
	strcpy(main_map->libname, "main");
	other_map = xzalloc(sizeof(*other_map) + 16);
	strcpy(other_map->libname, "other");

	pr_dbg("check simple match with default module\n");
	fill_pattern_list(&patch_patterns, "abc;!def", "", "main", PATT_SIMPLE);

	TEST_EQ(match_pattern_list(main_map, NULL, "abc", &patch_patterns), true);
	TEST_EQ(match_pattern_list(main_map, NULL, "def", &patch_patterns), false);
	TEST_EQ(match_pattern_list(other_map, NULL, "xyz", &patch_patterns), false);

	release_pattern_list(&patch_patterns);

	pr_dbg("check negative regex match with default module\n");
	fill_pattern_list(&patch_patterns, "!^a", "", "main", PATT_REGEX);

	TEST_EQ(match_pattern_list(main_map, NULL, "abc", &patch_patterns), false);
	TEST_EQ(match_pattern_list(main_map, NULL, "def", &patch_patterns), true);
	TEST_EQ(match_pattern_list(other_map, NULL, "xyz", &patch_patterns), false);

	release_pattern_list(&patch_patterns);

	pr_dbg("check exclusion regex with default module\n");
	fill_pattern_list(&patch_patterns, "!abc", "def", "main", PATT_SIMPLE);

	TEST_EQ(match_pattern_list(main_map, NULL, "abc", &patch_patterns), false);
	TEST_EQ(match_pattern_list(main_map, NULL, "def", &patch_patterns), false);
	TEST_EQ(match_pattern_list(main_map, NULL, "xyz", &patch_patterns), true);

	release_pattern_list(&patch_patterns);

	pr_dbg("check wildcard match with other module\n");
	fill_pattern_list(&patch_patterns, "*@other", "", "main", PATT_GLOB);

	TEST_EQ(match_pattern_list(main_map, NULL, "abc", &patch_patterns), false);
	TEST_EQ(match_pattern_list(main_map, NULL, "def", &patch_patterns), false);
	TEST_EQ(match_pattern_list(other_map, NULL, "xyz", &patch_patterns), true);

	release_pattern_list(&patch_patterns);

	free(main_map);
	free(other_map);

	return TEST_OK;
}

struct test_map_data {
	struct mcount_dynamic_info *mdi;
};

/* callback for dl_iterate_phdr() */
static int setup_test_map(struct dl_phdr_info *info, size_t sz, void *data)
{
	struct test_map_data *tmd = data;
	struct mcount_dynamic_info *mdi;
	struct uftrace_mmap *map;
	struct uftrace_module *mod;
	static struct sym syms[] = {
		{ 0x100, 0x100, ST_LOCAL_FUNC, "a" },
		{ 0x200, 0x100, ST_LOCAL_FUNC, "b" },
		{ 0x300, 0x100, ST_LOCAL_FUNC, "c" },
	};

	mdi = create_mdi(info);

	map = xzalloc(sizeof(*map) + 16);
	map->start = info->dlpi_addr;
	map->end = map->start + 0x1000;
	strcpy(map->libname, "main");
	map->len = strlen(map->libname);
	mcount_memcpy1(map->prot, "r-xp", 4);

	mod = xzalloc(sizeof(*mod) + 16);
	strcpy(mod->name, "main");
	mod->symtab.sym = syms;
	mod->symtab.nr_sym = ARRAY_SIZE(syms);

	map->mod = mod;
	mdi->map = map;
	tmd->mdi = mdi;

	return 1;
};

static void cleanup_test_map(struct mcount_dynamic_info *mdi)
{
	struct uftrace_mmap *map = mdi->map;
	struct uftrace_module *mod = map->mod;

	free(mod);
	free(map);
	free(mdi);
}

TEST_CASE(dynamic_find_badsym)
{
	struct test_map_data tmd = {};
	unsigned long base;

	pr_dbg("setup test map info\n");
	dl_iterate_phdr(setup_test_map, &tmd);
	base = tmd.mdi->map->start;

	pr_dbg("adding bad symbols\n");
	TEST_EQ(mcount_add_badsym(tmd.mdi, 0, base + 0x100), false);
	TEST_EQ(mcount_add_badsym(tmd.mdi, 0, base + 0x234), true);

	pr_dbg("finding bad symbols\n");
	TEST_EQ(mcount_find_badsym(tmd.mdi, base + 0x100), NULL);
	TEST_NE(mcount_find_badsym(tmd.mdi, base + 0x234), NULL);  /* found */
	TEST_EQ(mcount_find_badsym(tmd.mdi, base + 0x369), NULL);

	pr_dbg("cleanup test map info\n");
	mcount_free_badsym(tmd.mdi);
	cleanup_test_map(tmd.mdi);

	return TEST_OK;
}
#endif  /* UNIT_TEST */
