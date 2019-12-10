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
       struct page *page;
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

static int uncached_find_page(pte_t *pte, unsigned long addr,
    unsigned long next, struct mm_walk *walk)
{
  struct vm_area_struct *vma = walk->vma;
 struct page *page;
 //struct vm_fault *vmf = walk->private;
 void *addr1 = walk->private;

 page = vm_normal_page(vma, addr, *pte);
 if (page)
  return -EINVAL;
    addr1 = kmap_atomic(page);
    printk("%s():: found a reference page:%s\n", __func__, (unsigned char*)addr1);
 return 0;
}

static const struct mm_walk_ops uncached_walk_ops = {
 .pte_entry = uncached_find_page,
};

static vm_fault_t uncached_fault(struct vm_fault *vmf)
{
  int error, flag = 0;
  struct file *file = vmf->vma->vm_file;
  struct file *fpin = NULL;
  struct address_space *mapping = file->f_mapping;
  struct file_ra_state *ra = &file->f_ra;
  struct inode *inode = mapping->host;
  pgoff_t offset = vmf->pgoff;
  pgoff_t max_off;
  struct page *page = NULL;
  vm_fault_t ret = 0;
  void *addr;
  struct vm_area_struct *vma_iter, *vma_prev = NULL;
  struct securemem_state *state = vmf->vma->vm_file->private_data;

  printk("%s() 1::flags::%lu atomic_get(&mapping->i_mmap_writable) %d\n", __func__, vmf->vma->vm_flags, atomic_read(&mapping->i_mmap_writable));

  if ((vmf->vma->vm_flags & VM_SHARED) && (atomic_read(&mapping->i_mmap_writable) > 1))
        {
          //we need to find correct page 
          printk("%s()::need to find correct page to refer\n", __func__);
          //i_mmap_lock_read(mapping);
          vma_interval_tree_foreach(vma_iter, &mapping->i_mmap, offset, offset) {
            //need to find the parent vma and the phys page it references to
              if (vma_iter == vmf->vma){
                // found our vma, parent is previous
                walk_page_range(vma_prev->vm_mm, vma_prev->vm_start, vma_prev->vm_end, &uncached_walk_ops, addr);
                printk("%s()::walk_page_range done\n", __func__);
                if (addr){
                  printk("%s():: found reference page:%s\n", __func__, (unsigned char*)addr);
                } else {
                  printk("%s():: no addr\n", __func__);
                }
                break;
              }
            vma_prev = vma_iter;
          }
         // i_mmap_unlock_read(mapping);
          if (page){
            printk("%s()::found parent vma\n", __func__);
            dump_vma(vma_prev);
            addr = kmap_atomic(page);
            printk("%s():: and a reference page:%s\n", __func__, (unsigned char*)addr);
            vmf->page = page;
            return 0;
          }
          else
            return vmf_error(-ENOMEM); 
        } else {
            printk("%s()::need to allocate a new one\n", __func__);
            page = alloc_page(GFP_HIGHUSER_MOVABLE);
            if (!page)
            return vmf_error(-ENOMEM);

            if (PageSecret(page))
              printk("%s()::flag set before::%lu\n", __func__, page->flags);
            else
              printk("%s()::flag not set before::%lu\n", __func__, page->flags);

            SetPageSecret(page);
           
            if (PageSecret(page))
              printk("%s()::flag set::%lu\n", __func__, page->flags);
            else
              printk("%s()::flag nt set::%lu\n", __func__, page->flags);

            vmf->page = page;

            return 0;
      }
    
}

static const struct vm_operations_struct uncached_vm_ops = {
       .fault = uncached_fault,
};

static int securemem_mmap(struct file *file, struct vm_area_struct *vma)
{
       struct securemem_state *state = file->private_data;
       unsigned long mode = state->mode;
       struct address_space *mapping = file->f_mapping;

       switch (mode) {
       case SECUREMEM_EXCLUSIVE:
               vma->vm_ops = &exclusivemem_vm_ops;
               break;
       case SECUREMEM_UNCACHED:
               printk("%s():: vm_flags before:%lu, file %lu\n", __func__, vma->vm_flags, (unsigned long)file);
               printk("vma:");
               dump_vma(vma);
               vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
               vma->vm_ops = &uncached_vm_ops;
               vma->vm_flags |= VM_UNCACHED;
               printk("%s():: vm_flags after:%lu\n", __func__, vma->vm_flags);
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

      printk("%s():: file :%lu\n", __func__, (unsigned long)file);

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
