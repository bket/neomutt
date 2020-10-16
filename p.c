// gcc -I. -o p{,.c} lib{debug,maildir,hcache,compress,store,core,config,email,address,mutt}.a -lpcre2-8 -lidn2 -ltokyocabinet -lrocksdb -ltdb -llmdb -lkyotocabinet -lgdbm -lqdbm -ldb-5.3 -llz4 -lz -lzstd

#include "config.h"
#include <dirent.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "mutt/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "debug/lib.h"
#include "maildir/lib.h"
#include "copy.h"
#include "maildir/mdata.h"
#include "maildir/mdemail.h"
#include "maildir/private.h"
#include "mx.h"
#include "progress.h"
#ifdef USE_HCACHE
#include "hcache/lib.h"
#endif

bool C_Autocrypt = false;
bool C_FlagSafe = false;
bool C_MailCheckRecent = false;
char *HomeDir = NULL;
bool MonitorContextChanged = false;
char *ShortHostname = NULL;
SIG_ATOMIC_VOLATILE_T SigInt = 0;
struct Context *Context = NULL;

// Flags for maildir_mbox_check()
#define MMC_NO_DIRS 0        ///< No directories changed
#define MMC_NEW_DIR (1 << 0) ///< 'new' directory changed
#define MMC_CUR_DIR (1 << 1) ///< 'cur' directory changed

#define mutt_set_flag(m, e, flag, bf) mutt_set_flag_update(m, e, flag, bf, true)

const struct Mapping Fields[] = { 0 };
const struct Mapping ComposeFields[] = { 0 };

int nm_update_filename(struct Mailbox *m, const char *old_file, const char *new_file, struct Email *e)
{
  if (!m || !old_file || !new_file || !e)
    return -1;
  return 0;
}

void mutt_encode_path(struct Buffer *buf, const char *src)
{
  char *p = mutt_str_dup(src);
  int rc = mutt_ch_convert_string(&p, C_Charset, "us-ascii", 0);
  size_t len = mutt_buffer_strcpy(buf, (rc == 0) ? NONULL(p) : NONULL(src));

  /* convert the path to POSIX "Portable Filename Character Set" */
  for (size_t i = 0; i < len; i++)
  {
    if (!isalnum(buf->data[i]) && !strchr("/.-_", buf->data[i]))
    {
      buf->data[i] = '_';
    }
  }
  FREE(&p);
}

struct MuttWindow *dialog_find(struct MuttWindow *win)
{
  if (!win)
    return NULL;
  return NULL;
}

struct Message *mx_msg_open_new(struct Mailbox *m, const struct Email *e, MsgOpenFlags flags)
{
  if (!m || !e)
    return NULL;
  if (flags)
  {
  }
  return NULL;
}

int mx_msg_close(struct Mailbox *m, struct Message **msg)
{
  if (!m || !msg || !*msg)
    return 0;

  return 0;
}

int mutt_copy_message(FILE *fp_out, struct Mailbox *m, struct Email *e, CopyMessageFlags cmflags, CopyHeaderFlags chflags, int wraplen)
{
  if (!fp_out || !m || !e)
    return -1;
  if (cmflags || chflags || wraplen)
  {
  }
  return 0;
}

void mutt_set_flag_update(struct Mailbox *m, struct Email *e, int flag, bool bf, bool upd_mbox)
{
  if (!m || !e)
    return;
  if (flag || bf | upd_mbox)
    return;
}

void nm_edata_free(void **ptr)
{
  if (ptr)
  {
  }
}

void mx_alloc_memory(struct Mailbox *m)
{
  size_t s = MAX(sizeof(struct Email *), sizeof(int));

  if ((m->email_max + 25) * s < m->email_max * s)
  {
    mutt_error(_("Out of memory"));
    mutt_exit(1);
  }

  m->email_max += 25;
  if (m->emails)
  {
    mutt_mem_realloc(&m->emails, sizeof(struct Email *) * m->email_max);
    mutt_mem_realloc(&m->v2r, sizeof(int) * m->email_max);
  }
  else
  {
    m->emails = mutt_mem_calloc(m->email_max, sizeof(struct Email *));
    m->v2r = mutt_mem_calloc(m->email_max, sizeof(int));
  }
  for (int i = m->email_max - 25; i < m->email_max; i++)
  {
    m->emails[i] = NULL;
    m->v2r[i] = -1;
  }
}

int mutt_autocrypt_process_autocrypt_header(struct Email *e, struct Envelope *env)
{
  if (e || env)
  {
  }
  return 0;
}

void mutt_progress_init(struct Progress *progress, const char *msg, enum ProgressType type, size_t size)
{
  if (progress || msg || type || size)
  {
  }
}

void mutt_progress_update(struct Progress *progress, size_t pos, int percent)
{
  if (progress || pos || percent)
  {
  }
}

static void maildir_canon_filename2(char *name)
{
  if (!name)
    return;

  char *u = strpbrk(name, ",:");
  if (u)
    *u = '\0';
}

static int scan_dir(struct MdEmailArray *mda, const char *dir, struct Progress *progress)
{
  if (!mda || !dir)
    return -1;

  DIR *dirp = opendir(dir);
  if (!dirp)
  {
    mutt_perror("%s", dir);
    return -1;
  }

  mutt_debug(LL_DEBUG1, "Scanning: %s\n", dir);
  int count = 0;
  struct dirent *de = NULL;
  while ((SigInt != 1) && ((de = readdir(dirp))))
  {
    if (*de->d_name == '.')
      continue;

    mutt_debug(LL_DEBUG2, "    %s\n", de->d_name);
    mutt_progress_update(progress, ARRAY_SIZE(mda) + 1, -1);

    struct MdEmail *entry = maildir_entry_new();
    entry->canon_fname = strdup(de->d_name);
    ARRAY_ADD(mda, entry);
    count++;
  }

  closedir(dirp);

  if (SigInt == 1)
  {
    mutt_debug(LL_DEBUG1, "Scan aborted after %d files\n", count);
    SigInt = 0;
    return -2; // action aborted
  }

  mutt_debug(LL_DEBUG1, "Successfully found %d files\n", count);
  return count;
}

int mbox_observer(struct NotifyCallback *nc)
{
  if (!nc)
    return -1;

  debug_notify_observer(nc);
  return 0;
}

int main(int argc, char *argv[])
{
  MuttLogger = log_disp_terminal;
  const char *dir = "/home/mail/linode/neo";

  C_HeaderCache = "/home/mutt/.cache/mutt/";
  C_HeaderCacheBackend = "lmdb";
  C_Charset = "utf-8";

  if (argc == 2)
    dir = argv[1];

  struct ConfigSet *cs = cs_new(1024);
  NeoMutt = neomutt_new(cs);
  struct Account *a = account_new(NULL, NeoMutt->sub);
  neomutt_account_add(NeoMutt, a);

  printf("reading: %s\n", dir);
  struct Progress progress = { 0 };
  mutt_progress_init(&progress, "Maildir", MUTT_PROGRESS_READ, 0);
#if 0
  struct Mailbox *m = mailbox_new();
  m->type = MUTT_MAILDIR;
  m->verbose = true;
  notify_observer_add(m->notify, NT_MAILBOX, mbox_observer, NULL);

  mutt_buffer_strcpy(&m->pathbuf, dir);
#endif

  struct Buffer *buf = mutt_buffer_pool_get();
  struct MdEmailArray mda = ARRAY_HEAD_INITIALIZER;

  mutt_buffer_printf(buf, "%s/cur", dir);

  int cur_count = scan_dir(&mda, mutt_b2s(buf), &progress);
  // printf("count = %d\n", cur_count);

  struct MdEmail *md = NULL;
  struct MdEmail **mdp = NULL;
  ARRAY_FOREACH(mdp, &mda)
  {
    md = *mdp;

    struct Email *e = email_new();
    struct MaildirEmailData *edata = maildir_edata_new();
    e->edata = edata;
    e->edata_free = maildir_edata_free;
    e->old = true;

    mutt_str_asprintf(&e->path, "%s/%s", mutt_b2s(buf), md->canon_fname);
    maildir_parse_flags(e, e->path);

    md->email = e;
    maildir_canon_filename2(md->canon_fname);
    edata->canon_fname = md->canon_fname;
    md->canon_fname = NULL;
    // printf("    %s\n", e->path);
  }

  mutt_buffer_printf(buf, "%s/new", dir);

  // int new_count =
  scan_dir(&mda, mutt_b2s(buf), &progress);
  // printf("count = %d\n", cur_count + new_count);

  ARRAY_FOREACH_FROM(mdp, &mda, cur_count)
  {
    md = *mdp;

    struct Email *e = email_new();
    struct MaildirEmailData *edata = maildir_edata_new();
    e->edata = edata;
    e->edata_free = maildir_edata_free;

    mutt_str_asprintf(&e->path, "%s/%s", mutt_b2s(buf), md->canon_fname);
    maildir_parse_flags(e, e->path);

    md->email = e;
    maildir_canon_filename2(md->canon_fname);
    edata->canon_fname = md->canon_fname;
    md->canon_fname = NULL;
    // printf("    %s\n", e->path);
  }

  struct Mailbox *m = mailbox_new();
  mutt_buffer_strcpy(&m->pathbuf, dir);
  m->realpath = mutt_buffer_strdup(&m->pathbuf);
  m->type = MUTT_MAILDIR;
  m->verbose = true;
  maildir_delayed_parsing(m, &mda, &progress);
  maildir_move_to_mailbox(m, &mda);

  account_mailbox_add(a, m);

  // dump_graphviz("index");
  // for (int i = 0; i < m->email_max; i++)
  //   dump_graphviz_email(m->emails[i], i);

  // mailbox_free(&m);
  maildirarray_clear(&mda);
  mutt_buffer_pool_release(&buf);
  neomutt_free(&NeoMutt);
  cs_free(&cs);

#if 0
  int rc = maildir_read_dir(m, "cur");
  printf("old rc = %d\n", rc);
  rc = maildir_read_dir(m, "new");
  printf("new rc = %d\n", rc);
#endif

#if 0
  int rc = maildir_mbox_open(m);
  printf("maildir_mbox_open rc = %d\n", rc);

  for (int i = 0; i < m->email_max; i++)
  {
    struct Email *e = m->emails[i];
    struct MaildirEmailData *edata = maildir_edata_get(e);
    if (!e || !edata)
      continue;
    printf("%s\t%s\n", e->read ? "old" : "new", e->path);
  }
#endif

#if 0
  notify_observer_remove(m->notify, mbox_observer, NULL);
  mailbox_free(&m);
#endif
  return 0;
}
