// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/set_memory.h>
#include <linux/pagewalk.h>

#include <asm/tlb.h>

#define SECUREMEM 0xba
#define SET_EXCLUSIVE  _IOWR(SECUREMEM, 0x13, unsigned long)
#define SET_UNCACHED   _IOWR(SECUREMEM, 0x14, unsigned long)

#define SECUREMEM_EXCLUSIVE    0x23
#define SECUREMEM_UNCACHED     0x24

struct securemem_state {
       unsigned long mode;
};

static struct page *exclusivemem_get_page(struct securemem_state *state)
{
       /*
        * FIXME: implement a pool of huge pages to minimize direct map splits
        */
       return alloc_page(GFP_KERNEL);
}

static vm_fault_t exclusivemem_fault(struct vm_fault *vmf)
{
       struct securemem_state *state = vmf->vma->vm_file->private_data;
       unsigned long addr;
       struct page *page;

       page = exclusivemem_get_page(state);
       if (!page)
               return vmf_error(-ENOMEM);
       addr = (unsigned long)page_address(page);
       pr_debug("%s: p: %px, addr: %lx\n", __func__, page, addr);

#if 0
       /*
        * FIXME: we cannot really drop the page from the direct map
        * until we have a way to reinstate it there
        */
       if (set_direct_map_invalid_noflush(page)) {
               __free_page(page);
               return vmf_error(-ENOMEM);
       }

       flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
#endif

       vmf->page = page;
       return 0;
}

static const struct vm_operations_struct exclusivemem_vm_ops = {
       .fault = exclusivemem_fault,
};

static vm_fault_t uncached_fault(struct vm_fault *vmf)
{
  struct page *page;

  page = alloc_page(GFP_HIGHUSER_MOVABLE);
  if (!page)
    return vmf_error(-ENOMEM);

  SetPageSecret(page);

  vmf->page = page;

  return 0;
}

static const struct vm_operations_struct uncached_vm_ops = {
       .fault = uncached_fault,
};

static int securemem_mmap(struct file *file, struct vm_area_struct *vma)
{
       struct securemem_state *state = file->private_data;
       unsigned long mode = state->mode;

       switch (mode) {
       case SECUREMEM_EXCLUSIVE:
               vma->vm_ops = &exclusivemem_vm_ops;
               break;
       case SECUREMEM_UNCACHED:
               vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
               vma->vm_ops = &uncached_vm_ops;
               vma->vm_flags |= VM_UNCACHED;
               /* setup the PG_secret flag upon pages */
               mark_pages_secret(vma);
               break;
       default:
               return -EINVAL;
       }

       return 0;
}

static long securemem_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
       struct securemem_state *state = file->private_data;
       unsigned long mode = state->mode;

       if (mode)
               return -EINVAL;

       switch (cmd) {
       case SET_EXCLUSIVE:
               mode = SECUREMEM_EXCLUSIVE;
               break;
       case SET_UNCACHED:
               mode = SECUREMEM_UNCACHED;
               break;
       default:
               return -EINVAL;
       }

       state->mode = mode;

       return 0;
}

static int securemem_open(struct inode *inode, struct file *file)
{
       struct securemem_state *state;

       state = kzalloc(sizeof(*state), GFP_KERNEL);
       if (!state)
               return -ENOMEM;

       file->private_data = state;

       return 0;
}

const struct file_operations securemem_fops = {
       .open           = securemem_open,
       .mmap           = securemem_mmap,
       .unlocked_ioctl = securemem_ioctl,
       .compat_ioctl   = securemem_ioctl,
};
