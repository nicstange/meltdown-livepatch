/*
 * pgtable-generic.c
 *
 * Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "kaiser.h"
#include "pgtable-generic.h"

/* Patched, calls pgd_clear() */
void kgr_pgd_clear_bad(pgd_t *pgd)
{
	pgd_ERROR(*pgd);
	kgr_pgd_clear(pgd);
}
