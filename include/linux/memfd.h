/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_MEMFD_H
#define __LINUX_MEMFD_H

#include <linux/file.h>

#ifdef CONFIG_MEMFD_CREATE
extern long memfd_fcntl(struct file *file, unsigned int cmd, unsigned long arg);
#else
static inline long memfd_fcntl(struct file *f, unsigned int c, unsigned long a)
{
	return -EINVAL;
}
#endif

#ifdef CONFIG_MEMFD_SECRETMEM
extern struct file *secretmem_file_create(const char *name, unsigned int flags);
#else
static inline struct file *secretmem_file_create(const char *name, unsigned int flags)
{
       return ERR_PTR(-EINVAL);
}
#endif

#endif /* __LINUX_MEMFD_H */
