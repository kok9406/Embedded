/* Copyright 2011-2013 Bert Muennich
 *
 * This file is part of sxiv.
 *
 * sxiv is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * sxiv is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with sxiv.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _POSIX_C_SOURCE 200112L
#define _MAPPINGS_CONFIG

//keypad header file
#include <termios.h>
#include <stdio.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <asm/ioctls.h>

//define for keypad
#define KEY_NUM1	1
#define KEY_NUM2	2
#define KEY_NUM3	3
#define KEY_NUM4	4
#define KEY_NUM5	5
#define KEY_NUM6	6
#define KEY_NUM7	7
#define KEY_NUM8	8
#define KEY_NUM9	9
#define KEY_NUM10	10
#define KEY_NUM11	11
#define KEY_NUM12	12
#define KEY_NUM13	13
#define KEY_NUM14	14
#define KEY_NUM15	15
#define KEY_NUM16	16

#define dbg(x...)	printf(x)

//static source for keypad
static char keyDev[] = "/dev/KEY";
static int keyFD = (-1);

#include <vector.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <locale.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <X11/keysym.h>
#include <X11/XF86keysym.h>

#include "types.h"
#include "commands.h"
#include "image.h"
#include "options.h"
#include "thumbs.h"
#include "util.h"
#include "window.h"
#include "config.h"

//scan input to keypad - uart
unsigned char getKey(int tmo)
{
	unsigned char b;
	if (tmo) 
	{
		if (tmo < 0)
			tmo = ~tmo * 1000;
		else
			tmo *= 1000000;
		while (tmo > 0) 
		{
			usleep(10000);
			ioctl(keyFD, FIONREAD, &b);
			if (b)
				return (b);
			tmo -= 10000;
		}
		return (-1);
	}
	else 

		read(keyFD, &b, sizeof(b));
	}
}

enum 
{
	FILENAME_CNT = 1024,
	TITLE_LEN = 256
};

typedef struct 
{
	const char* name;
	char* cmd;
} exec_t;

typedef struct 
{
	struct timeval when;
	bool active;
	timeout_f handler;
} timeout_t;

/* timeout handler functions: */
void redraw(void);
void reset_cursor(void);
void animate(void);
void slideshow(void);
void clear_resize(void);

appmode_t mode;
img_t img;
tns_t tns;
win_t win;

fileinfo_t* files;
int filecnt, fileidx;
int alternate;

int prefix;
bool extprefix;

bool resized = false;

struct 
{
	char* cmd;
	int fd;
	unsigned int i, lastsep;
	bool open;
} info;

struct
{
	char* cmd;
	bool warned;
} keyhandler;

timeout_t timeouts[] = 
{
   { { 0, 0 }, false, redraw       },
   { { 0, 0 }, false, reset_cursor },
   { { 0, 0 }, false, animate      },
   { { 0, 0 }, false, slideshow    },
   { { 0, 0 }, false, clear_resize },
};

void cleanup(void)                                 //false ���� �ƴϸ� in�� ture�� �ϰ� img�� �ݰ�, �ּ� �ʱ�ȭ, win �ݰ�
{
	static bool in = false;

	if (!in) 
	{
		in = true;
		img_close(&img, false);
		tns_free(&tns);
		win_close(&win);
	}
}

void check_add_file(char* filename)
{
	const char* bn;

	if (filename == NULL || *filename == '\0')            //�����̸��� ���ų� �ּҾȿ� �ƹ��͵� ������
		return;

	if (access(filename, R_OK) < 0) 
	{                  //access : ���� ���� ����, filename ���, mode �������� ����� 0, ������ -1                              
		warn("could not open file: %s", filename);         //������ ��������
		return;
	}

	if (fileidx == filecnt) 
	{                        //fileidx�� filent�϶� filecnt�� 2�� ���ϰ�
		filecnt *= 2;
		files = (fileinfo_t*)s_realloc(files, filecnt * sizeof(fileinfo_t)); //realloc : �������� �Ҵ��� �޸��� ũ�� ����(ù���� : ���� �������� �Ҵ� �޸� �ּ�, ���� �Ҵ��� �޸� ũ��)
	}                                                         //realloc�� ���� fileinfo_t*���� cast�ؼ� files�� ����

#if defined _BSD_SOURCE || defined _XOPEN_SOURCE && \                     //BSD_SOURCE, XOPEN_SOURCE, �ƹ��͵� �������
	((_XOPEN_SOURCE - 0) >= 500 || defined _XOPEN_SOURCE_EXTENDED)            //XOPEN_SOUCRE - 0 �� 500���� ũ�ų� _XOPEN_SOURCE_EXTENDED ���ǵ������

		if ((files[fileidx].path = realpath(filename, NULL)) == NULL) 
		{            //files[fileidx]�� path�� ������(filename.NULL)�̰� �̰� NULL�̸� realpath�� �ƴ϶�� ���
			warn("could not get real path of file: %s\n", filename);
			return;
		}
#else
	if (*filename != '/') 
	{                                          //filename�� �ּҰ��� '/'�� �ƴϸ�
		if ((files[fileidx].path = absolute_path(filename)) == NULL)
		{         //files[fileidx]�� path�� �������̰� �̰� NULL�̸� ������ �ƴ϶�� ��� �ٿ�
			warn("could not get absolute path of file: %s\n", filename);
			return;
		}
	}
	else 
	{
		files[fileidx].path = NULL;                                    //files[fileidx].path�� NULL�̴�
	}
#endif

	files[fileidx].loaded = false;                                    //files[fileidx] �ε� ����
	files[fileidx].name = s_strdup(filename);                           //files[fileidx]�� name�� (filename�� ���� + 1)�ؼ� return, s�� ������ �޸� �Ҵ����� ����( util.c )
	if (files[fileidx].path == NULL)
		files[fileidx].path = files[fileidx].name;                        //   files[fileidx]��ΰ� NULL�̸� files[fileidx]�� name�� (filename�� ���� + 1)�ؼ� return, s�� ������ �޸� �Ҵ����� ����( util.c )
	if ((bn = strrchr(files[fileidx].name, '/')) != NULL && bn[1] != '\0')      // bn( files[fileidx].name�� �������� '/'�� ������ �� �ּҸ� ��ȯ)�� NULL �ƴϰ� bn[1]�� NULL�� �ƴϸ�
		files[fileidx].base = ++bn;                                    //files[fileidx].base = ++bn;   
	else
		files[fileidx].base = files[fileidx].name;                        //files[fileidx].base = files[fileidx].name�̴�.                              
	fileidx++;
}

void remove_file(int n, bool manual)                                 //���� ����   ( bool : ture , false ����         )               
{
	if (n < 0 || n >= filecnt)
		return;

	if (filecnt == 1) 
	{
		if (!manual)
			fprintf(stderr, "sxiv: no more files to display, aborting\n");         //filecnt == 1 �̰� manual�� �ƴϸ� ���� ���� �˸�         
		cleanup();
		exit(manual ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	if (files[n].path != files[n].name)                                    //files[n].path != files[n].name �̸� �Ѵ� free ��Ŵ
	{
		free((void*)files[n].path);
		free((void*)files[n].name);
	}

	if (n + 1 < filecnt)
		memmove(files + n, files + n + 1, (filecnt - n - 1) * sizeof(fileinfo_t));   //memove:(����Ǵ� �޸��� ù���� �ּ�, ������ �޸��� ù���� �ּ�,������ũ��)
	if (n + 1 < tns.cnt) 
	{
		memmove(tns.thumbs + n, tns.thumbs + n + 1, (tns.cnt - n - 1) * sizeof(thumb_t));       //memove:(����Ǵ� �޸��� ù���� �ּ�, ������ �޸��� ù���� �ּ�,������ũ��)
		memset(tns.thumbs + tns.cnt - 1, 0, sizeof(thumb_t));                           //memset : (������ �޸𸮺��� ù�ּ�, ������ ��, ������ �޸��� ���� ũ��)      
	}

	filecnt--;
	if (n < tns.cnt)
		tns.cnt--;
	if (n < alternate)
		alternate--;
}

void set_timeout(timeout_f handler, int time, bool overwrite)
{
	int i;

	for (i = 0; i < ARRLEN(timeouts); i++) 
	{
		if (timeouts[i].handler == handler) 
		{
			if (!timeouts[i].active || overwrite)
			{
				gettimeofday(&timeouts[i].when, 0);
				TV_ADD_MSEC(&timeouts[i].when, time);
				timeouts[i].active = true;
			}
			return;
		}
	}
}

void reset_timeout(timeout_f handler)
{
	int i;

	for (i = 0; i < ARRLEN(timeouts); i++) 
	{
		if (timeouts[i].handler == handler) 
		{
			timeouts[i].active = false;
			return;
		}
	}
}

bool check_timeouts(struct timeval* t)
{
	int i = 0, tdiff, tmin = -1;
	struct timeval now;

	while (i < ARRLEN(timeouts)) 
	{
		if (timeouts[i].active) 
		{
			gettimeofday(&now, 0);
			tdiff = TV_DIFF(&timeouts[i].when, &now);
			if (tdiff <= 0) 
			{
				timeouts[i].active = false;
				if (timeouts[i].handler != NULL)
					timeouts[i].handler();
				i = tmin = -1;
			}
			else if (tmin < 0 || tdiff < tmin) 
			{
				tmin = tdiff;
			}
		}
		i++;
	}
	if (tmin > 0 && t != NULL)
		TV_SET_MSEC(t, tmin);
	return tmin > 0;
}

void open_info(void)                                                //open ����
{
	static pid_t pid;
	int pfd[2];

	if (info.cmd == NULL || info.open || win.bar.h == 0)                     //info��� ����ü ���� (info.cmd == NULL || info.open || win.bar.h == 0)         
		return;
	if (info.fd != -1) 
	{                                             //info.fd != -1�̸� close(info.fd
		close(info.fd);                                                //info.fd�� �ݴ´�      
		kill(pid, SIGTERM);                                             //SIGTERM : Software termination signal from kill               
		info.fd = -1;
	}
	win.bar.l[0] = '\0';

	if (pipe(pfd) < 0)
		return;
	pid = fork();                                                   //pid �� fork()�̸�         
	if (pid > 0) 
	{                                                   //parent ����            
		close(pfd[1]);                                                //pfd[1]�� �ݰ� pfd[0]�� Ư���� ����
		fcntl(pfd[0], F_SETFL, O_NONBLOCK);                                 //fcntl : (������ ������  ���� �����, ���� ����ڿ� ���� Ư���� �����ϴ� �Ű�����, �ι������ڿ� ���� �����Ǵ� �������� ��)
		info.fd = pfd[0];                                             //info.fd = pfd[0] �ϰ� , info.open�� ������
		info.i = info.lastsep = 0;
		info.open = true;
	}
	else if (pid == 0) 
	{                                             //children ����
		close(pfd[0]);                                                //pfd[0]�� �ݰ�, 
		dup2(pfd[1], 1);
		execl(info.cmd, info.cmd, files[fileidx].name, NULL);                  //info.cmd�� ������ ����� ������ ����                        
		warn("could not exec: %s", info.cmd);
		exit(EXIT_FAILURE);
	}
}

void read_info(void)                                                //read ���� (�о���� ���� n �� 0���� Ŀ�� ����)                                             
{
	ssize_t i, n;
	char buf[BAR_L_LEN];

	while (true) 
	{
		n = read(info.fd, buf, sizeof(buf));                              //n�� buf�� ���� info.fd�� �о� ����               
		if (n < 0 && errno == EAGAIN)                                    //n ���� 0���� �۰ų� errno��� �ּҰ� �����ڵ��̸�
			return;
		else if (n == 0)
			goto end;
		for (i = 0; i < n; i++)
		{
			if (buf[i] == '\n') 
			{
				if (info.lastsep == 0)
				{
					win.bar.l[info.i++] = ' ';
					info.lastsep = 1;
				}
			}
			else
			{
				win.bar.l[info.i++] = buf[i];
				info.lastsep = 0;
			}
			if (info.i + 1 == sizeof(win.bar.l))
				goto end;
		}
	}
end:
	info.i -= info.lastsep;
	win.bar.l[info.i] = '\0';
	win_update_bar(&win);
	close(info.fd);
	info.fd = -1;
	while (waitpid(-1, NULL, WNOHANG) > 0);
}

void load_image(int new)
{
	if (new < 0 || new >= filecnt)                                      //new�� 0����ũ�� filecent���� �۾ƾ���
		return;

	win_set_cursor(&win, CURSOR_WATCH);                                //Ŀ������ �ڵ���     
	reset_timeout(slideshow);

	if (new != fileidx)
		alternate = fileidx;

	img_close(&img, false);                                    //image.c�� �մµ� �ؼ� �Ұ�                                             
	while (!img_load(&img, &files[new])) 
	{                        //!img_load���н� ���ϻ���
		remove_file(new, false);
		if (new >= filecnt)
			new = filecnt - 1;
		else if (new > 0 && new < fileidx)
			new--;
	}
	files[new].loaded = true;
	fileidx = new;

	info.open = false;
	open_info();

	if (img.multi.cnt > 0 && img.multi.animate)
		set_timeout(animate, img.multi.frames[img.multi.sel].delay, true);
	else
		reset_timeout(animate);
}

void update_info(void)                                                      //update ����
{
	int sel;
	unsigned int i, fn, fw, n;
	unsigned int llen = sizeof(win.bar.l), rlen = sizeof(win.bar.r);
	char* lt = win.bar.l, * rt = win.bar.r, title[TITLE_LEN];
	const char* mark;
	bool ow_info;

	for (fw = 0, i = filecnt; i > 0; fw++, i /= 10);
	sel = mode == MODE_IMAGE ? fileidx : tns.sel;

	/* update window title */
	if (mode == MODE_THUMB) 
	{
		win_set_title(&win, "sxiv");                                             //thumb���� sxiv�� ���÷��� Ÿ��Ʋ ����
	}
	else 
	{
		snprintf(title, sizeof(title), "sxiv - %s", files[sel].name);                  //title�� files[sel].name�� title ������� ����
		win_set_title(&win, title);                                             //title�� ���÷��� Ÿ��Ʋ ����                                       
	}

	/* update bar contents */
	if (win.bar.h == 0)
		return;
	mark = files[sel].marked ? "* " : "";
	if (mode == MODE_THUMB) 
	{                                                //thumb�� mark
		if (tns.cnt == filecnt) 
		{
			n = snprintf(rt, rlen, "%s%0*d/%d", mark, fw, sel + 1, filecnt);
			ow_info = true;
		}
		else 
		{
			snprintf(lt, llen, "Loading... %0*d/%d", fw, tns.cnt, filecnt);
			rt[0] = '\0';
			ow_info = false;
		}
	}
	else {                                                         //image ���
		n = snprintf(rt, rlen, "%s", mark);
		if (img.ss.on)
			n += snprintf(rt + n, rlen - n, "%ds | ", img.ss.delay);
		if (img.gamma != 0)
			n += snprintf(rt + n, rlen - n, "G%+d | ", img.gamma);
		n += snprintf(rt + n, rlen - n, "%3d%% | ", (int)(img.zoom * 100.0));
		if (img.multi.cnt > 0) 
		{
			for (fn = 0, i = img.multi.cnt; i > 0; fn++, i /= 10);
			n += snprintf(rt + n, rlen - n, "%0*d/%d | ",
				fn, img.multi.sel + 1, img.multi.cnt);
		}
		n += snprintf(rt + n, rlen - n, "%0*d/%d", fw, sel + 1, filecnt);
		ow_info = info.cmd == NULL;
	}
	if (ow_info)
	{                                                      //text â��  text �ٿ�
		fn = strlen(files[sel].name);
		if (fn < llen &&
			win_textwidth(files[sel].name, fn, true) +
			win_textwidth(rt, n, true) < win.w)
		{
			strncpy(lt, files[sel].name, llen);                                           //lt�� files[sel].name�� llen ���̷� ����
		}
		else 
		{
			strncpy(lt, files[sel].base, llen);
		}
	}
}

void redraw(void)                                          //�̹��� ����� �Լ� ��ƴ         
{
	int t;

	if (mode == MODE_IMAGE) 
	{
		img_render(&img);                                    //�̹��� ����϶� �̹��� ����
		if (img.ss.on) 
		{
			t = img.ss.delay * 1000;
			if (img.multi.cnt > 0 && img.multi.animate)
				t = MAX(t, img.multi.length);                           //t �� img.multi.length�� ���ؼ� t�� �ִ´�
			set_timeout(slideshow, t, false);
		}
	}
	else
	{                                             //thumb����϶� �̹��� ����      
		tns_render(&tns);
	}
	update_info();
	win_draw(&win);
	reset_timeout(redraw);
	reset_cursor();
}

void reset_cursor(void)
{
	int i;
	cursor_t cursor = CURSOR_NONE;

	if (mode == MODE_IMAGE) 
	{                                    //�̹��� ��忡�� Ŀ�� ����                     
		for (i = 0; i < ARRLEN(timeouts); i++) 
		{
			if (timeouts[i].handler == reset_cursor)
			{
				if (timeouts[i].active)
					cursor = CURSOR_ARROW;
				break;
			}
		}
	}
	else {                                                //thumbs ��忡�� Ŀ�� ����            
		if (tns.cnt != filecnt)
			cursor = CURSOR_WATCH;
		else
			cursor = CURSOR_ARROW;
	}
	win_set_cursor(&win, cursor);                                 //Ŀ�� �����쿡 �ٿ��               
}

void animate(void)
{
	if (img_frame_animate(&img, false)) 
	{                           //img�� frame ���� ���⸦ �Ҿ�ִ´�
		redraw();
		set_timeout(animate, img.multi.frames[img.multi.sel].delay, true);
	}
}

void slideshow(void)
{
	load_image(fileidx + 1 < filecnt ? fileidx + 1 : 0);               //0�� filedix + 1�� ���ؼ� fileidx + 1 ���� �ε��̹����ϰ� redraw

	redraw();
}

void clear_resize(void)
{
	resized = false;
}

void run_key_handler(const char* key, unsigned int mask)
{
	pid_t pid;
	int retval, status, n = mode == MODE_IMAGE ? fileidx : tns.sel;
	char kstr[32];
	struct stat oldst, newst;

	if (keyhandler.cmd == NULL) 
	{											    //keyhandler.cmd  ������ ���
		if (!keyhandler.warned) 
		{
			warn("key handler not installed");
			keyhandler.warned = true;
		}
		return;
	}
	if (key == NULL)
		return;

	snprintf(kstr, sizeof(kstr), "%s%s%s%s",
		mask & ControlMask ? "C-" : "",
		mask & Mod1Mask ? "M-" : "",
		mask & ShiftMask ? "S-" : "", key);										//mask�� �ּ� controal mask, mod1mask, shiftmask�� kstr�� ����� �°� kstr�� ����

	stat(files[n].path, &oldst);												//oldst�� ���� files[n]�� ��η� �о��                           

	if ((pid = fork()) == 0)
	{													//children process ����                  
		execl(keyhandler.cmd, keyhandler.cmd, kstr, files[n].path, NULL);
		warn("could not exec key handler");
		exit(EXIT_FAILURE);
	}
	else if (pid < 0)
	{															//children process ���� ������
		warn("could not fork key handler");
		return;
	}
	win_set_cursor(&win, CURSOR_WATCH);											//winâ�� Ŀ�� ����            

	waitpid(pid, &status, 0);													//waitpid : ( wait�� �ڽ� ���μ��� ���� 0���� ũ�� wait , �ڽ��� ���� ��Ÿ�� , 0�̸� return �ҋ����� block)
	retval = WEXITSTATUS(status);												//(WEXITSTATUS( status) : �ڽ� ���μ����� ���� ����Ǿ��� �� ��ȯ�� ��) retval�� ��ȯ���� �ִ´�
	if (WIFEXITED(status) == 0 || retval != 0)									//(WIFEXITED( status) : �ڽ� ���μ����� ���������� ����Ǿ��ٸ� TRUE)   �� �ڽ��� �������� �Ǿ��ٸ�
		warn("key handler exited with non-zero return value: %d", retval);

	if (stat(files[n].path, &newst) == 0 &&										//newst�� ������ files[n]�� ��η� �о�°��� 0�̰�      &oldst.st_mtime, &newst.st_mtime�� ���ؼ� ������                        
		memcmp(&oldst.st_mtime, &newst.st_mtime, sizeof(oldst.st_mtime)) == 0)
	{
		/* file has not changed */
		win_set_cursor(&win, CURSOR_ARROW);										//������ ��ȭ�� �ʾ����Ƿ� Ŀ������� �ð������ϰ� ���   
		set_timeout(reset_cursor, TO_CURSOR_HIDE, true);
		return;
	}
	if (mode == MODE_IMAGE)
	{
		img_close(&img, true);													//�̹��� ���� �̹��� �����ϰ� fileidx�̹��� �ε�               
		load_image(fileidx);
	}
	if (!tns_load(&tns, n, &files[n], true, mode == MODE_IMAGE) &&				//thumb ����ϴ�
		mode == MODE_THUMB)
	{
		remove_file(tns.sel, false);
		tns.dirty = true;
		if (tns.sel >= tns.cnt)
			tns.sel = tns.cnt - 1;
	}
	redraw();
}

#define MODMASK(mask) ((mask) & (ShiftMask|ControlMask|Mod1Mask))

void on_keypress(XKeyEvent * kev)												//key�Է¿� ���� (�ʿ����)
{
	int i;
	unsigned int sh;
	KeySym ksym, shksym;
	char key;

	if (kev == NULL)
		return;

	if (kev->state & ShiftMask) 
	{
		kev->state &= ~ShiftMask;
		XLookupString(kev, &key, 1, &shksym, NULL);
		kev->state |= ShiftMask;
	}
	XLookupString(kev, &key, 1, &ksym, NULL);
	sh = (kev->state & ShiftMask) && ksym != shksym ? ShiftMask : 0;

	if (IsModifierKey(ksym))
		return;
	if (ksym == XK_Escape && MODMASK(kev->state) == 0) 
	{
		extprefix = False;
	}
	else if (extprefix)
	{
		run_key_handler(XKeysymToString(ksym), kev->state & ~sh);
		extprefix = False;
	}
	else if (key >= '0' && key <= '9')
	{
		/* number prefix for commands */
		prefix = prefix * 10 + (int)(key - '0');								//���� ��ɿ� ����
		return;
	}
	else for (i = 0; i < ARRLEN(keys); i++) 
	{
		if (keys[i].ksym == ksym &&
			MODMASK(keys[i].mask | sh) == MODMASK(kev->state) &&
			keys[i].cmd != NULL)
		{
			cmdreturn_t ret = keys[i].cmd(keys[i].arg);

			if (ret == CMD_INVALID)
				continue;
			if (ret == CMD_DIRTY)
				redraw();
			break;
		}
	}
	prefix = 0;
}

void on_buttonpress(XButtonEvent * bev)											//���콺 ��ư �Է¿� ���� (�ʿ����)9
{
	int i, sel;
	static Time firstclick;

	if (bev == NULL)
		return;

	if (mode == MODE_IMAGE)
	{
		win_set_cursor(&win, CURSOR_ARROW);
		set_timeout(reset_cursor, TO_CURSOR_HIDE, true);

		for (i = 0; i < ARRLEN(buttons); i++)
		{
			if (buttons[i].button == bev->button &&
				MODMASK(buttons[i].mask) == MODMASK(bev->state) &&
				buttons[i].cmd != NULL)
			{
				cmdreturn_t ret = buttons[i].cmd(buttons[i].arg);

				if (ret == CMD_INVALID)
					continue;
				if (ret == CMD_DIRTY)
					redraw();
				break;
			}
		}
	}
	else 
	{
		/* thumbnail mode (hard-coded) */
		switch (bev->button) 
		{
		case Button1:
			if ((sel = tns_translate(&tns, bev->x, bev->y)) >= 0) 
			{
				if (sel != tns.sel) 
				{
					tns_highlight(&tns, tns.sel, false);
					tns_highlight(&tns, sel, true);
					tns.sel = sel;
					firstclick = bev->time;
					redraw();
				}
				else if (bev->time - firstclick <= TO_DOUBLE_CLICK) 
				{
					mode = MODE_IMAGE;
					set_timeout(reset_cursor, TO_CURSOR_HIDE, true);
					load_image(tns.sel);
					redraw();
				}
				else 
				{
					firstclick = bev->time;
				}
			}
			break;
		case Button3:
			if ((sel = tns_translate(&tns, bev->x, bev->y)) >= 0) 
			{
				files[sel].marked = !files[sel].marked;
				tns_mark(&tns, sel, files[sel].marked);
				redraw();
			}
			break;
		case Button4:
		case Button5:
			if (tns_scroll(&tns, bev->button == Button4 ? DIR_UP : DIR_DOWN,
				(bev->state & ControlMask) != 0))
				redraw();
			break;
		}
	}
	prefix = 0;
}

void run(void)																	//input���� Ȯ���ϰ� �׿� �´� �̺�Ʈ�� �����ϴ� �Լ�, ��忡 �´� �̺�Ʈ (keypass,Ŀ��)�̷��� ����                     
{
	int xfd;
	fd_set fds;
	struct timeval timeout;
	bool discard, to_set;
	unsigned char c;
	XEvent ev, nextev;

	redraw();

	while (true) {
		while (mode == MODE_THUMB && tns.cnt < filecnt &&
			XPending(win.env.dpy) == 0)
		{
			/* load thumbnails */												//thumbnail �ε��ϰ� tns_load�Ǹ� tns.cnt ����            
			set_timeout(redraw, TO_REDRAW_THUMBS, false);
			if (tns_load(&tns, tns.cnt, &files[tns.cnt], false, false)) {
				tns.cnt++;
			}
			else {
				remove_file(tns.cnt, false);									//tns_load �ȵɽ� ���� ����   
				if (tns.sel > 0 && tns.sel >= tns.cnt)
					tns.sel--;
			}
			if (tns.cnt == filecnt)
				redraw();
			else
				check_timeouts(NULL);
		}

		while (XPending(win.env.dpy) == 0
			&& ((to_set = check_timeouts(&timeout)) || info.fd != -1))
		{
			/* check for timeouts & input */									//input Ȯ��   fds������ Ȯ���Ͽ� �����ϸ� read_info ����
			xfd = ConnectionNumber(win.env.dpy);
			FD_ZERO(&fds);														//fds������ ��� ��Ʈ ����
			FD_SET(xfd, &fds);													//fds������ xfd�� �ش��ϴ� ��Ʈ 1��                        
			if (info.fd != -1) {
				FD_SET(info.fd, &fds);											//info.fd�� -1�� �ƴϸ� fds������ info.fd�� ã��                        
				xfd = MAX(xfd, info.fd);										//xfd�� info.fd�� �ְ� xfd�� �̾Ƴ���
			}
			select(xfd + 1, &fds, 0, 0, to_set ? &timeout : NULL);				//select�Լ� : (�˻��ϰ� �ϴ� ���� +1, �б�� �ּ�, ����� �ּ�, ���ܼ� �ּ�,Ÿ�Ӿƿ��ð�����)         
			if (info.fd != -1 && FD_ISSET(info.fd, &fds))
				read_info();
		}

		do {																	//Xlib : c���α׷��� ���� �ۼ��� x ���� �ý��� �������� ũ���̾�Ʈ ���̺���
			XNextEvent(win.env.dpy, &ev);										//�̺�Ʈ ����⸦ ��ٸ��� �ִ� , �̺�Ʈ�� ���۵Ǹ� �Ʒ��ٷΰ��� � �̺�Ʈ���� �ĺ��ϴ� ���   
			discard = false;
			if (XEventsQueued(win.env.dpy, QueuedAlready) > 0) {				//�̺�Ʈ���� �̺�Ʈ�� ��� ����
				XPeekEvent(win.env.dpy, &nextev);
				switch (ev.type) {
				case ConfigureNotify:											//â���°� �ٲ�                        
					discard = ev.type == nextev.type;
					break;
				case KeyPress:													//Ű�� ������
					discard = (nextev.type == KeyPress || nextev.type == KeyRelease) && ev.xkey.keycode == nextev.xkey.keycode;
					break;
				}
			}
		} while (discard);

		switch (ev.type) {
			/* handle events */													//�̺�Ʈ handle                  
		case ButtonPress:														//��ư�� ������� ��ưpress�Լ�
			on_buttonpress(&ev.xbutton);
			break;
		case ClientMessage:														//�ٸ� Ŭ���̾�Ʈ�� �޼����� ����������         
			if ((Atom)ev.xclient.data.l[0] == atoms[ATOM_WM_DELETE_WINDOW])
				return;
			break;
		case ConfigureNotify:													//â�� ���°� �ٲ������                  
			if (win_configure(&win, &ev.xconfigure)) {							//�̹����� ���������� �̹������� thumbs��� ����
				if (mode == MODE_IMAGE) {
					img.dirty = true;
					img.checkpan = true;
				}
				else {
					tns.dirty = true;
				}
				if (!resized || win.fullscreen) {								//��忡 �°� resize�ؼ� redraw      
					redraw();
					set_timeout(clear_resize, TO_REDRAW_RESIZE, false);
					resized = true;
				}
				else {
					set_timeout(redraw, TO_REDRAW_RESIZE, false);
				}
			}
			break;
		case Expose:															//winâ�� ǥ��         
			win_expose(&win, &ev.xexpose);
			break;
		case KeyPress:															//Ű�Է�               
			on_keypress(&ev.xkey);
			break;
		case MotionNotify:														//���� �˸��� �̹�������ϰ�� win�� Ŀ�� ����         
			if (mode == MODE_IMAGE) {
				win_set_cursor(&win, CURSOR_ARROW);
				set_timeout(reset_cursor, TO_CURSOR_HIDE, true);
			}
			break;
		}

		//Event When Input Keypad
		c = getKey(10);
		switch (c) {
		case KEY_NUM1:
			dbg("RGB2GARY\n");
			break;
		case KEY_NUM2:
			dbg("MeanShift Filter\n");
			break;
		case KEY_NUM3:
			dbg("Local bynary pattern\n");
			break;
		case KEY_NUM4:
			dbg("Keep the Filter\n");
			break;
		case KEY_NUM5:
			dbg("Median Filter\n");
			break;
		case KEY_NUM6:
			dbg("Gaussain filter\n");
			break;
		case KEY_NUM7:
			dbg("Laplacian Filter\n");
			break;
		case KEY_NUM8:
			dbg("Reset Image\n");
			break;
		case KEY_NUM9:
			dbg("prev Image\n");
			break;
		case KEY_NUM10:
			dbg("Up\n");
			break;
		case KEY_NUM11:
			dbg("Next Image\n");
			break;
		case KEY_NUM12:
			dbg("../\n");
			break;
		case KEY_NUM13:
			dbg("Left\n");
			break;
		case KEY_NUM14:
			dbg("Down\n");
			break;
		case KEY_NUM15:
			dbg("Right\n");
			break;
		case KEY_NUM16:
			dbg("Enter\n");
			break;
		default: break;
		}
	}
}

int fncmp(const void* a, const void* b)
{
	return strcoll(((fileinfo_t*)a)->name, ((fileinfo_t*)b)->name);				//(fileinfo_t*) a)->name�� ((fileinfo_t*) b)->name�� �ٸ����� ��Ÿ�������� ��
}

int main(int argc, char** argv)
{
	int i, start;
	size_t n;
	ssize_t len;
	char* filename;
	const char* homedir, * dsuffix = "";
	struct stat fstats;
	if ((keyFD = open(keyDev, O_RDONLY)) < 0) {
		perror("Failed open /dev/KEY");
		exit(-1);
	}
	r_dir_t dir;

	parse_options(argc, argv);									                //Command option�� �ش� (��ɾ� ������ ������� d�� ���� �̷��� ) 

	if (options->clean_cache) {									                //option�� clean_cache�� thumbs �ʱ�ȭ,ĳ�õ� �ʱ�ȭ
		tns_init(&tns, 0, NULL);
		tns_clean_cache(&tns);
		exit(EXIT_SUCCESS);
	}

	if (options->filecnt == 0 && !options->from_stdin) {						//from_stdion : typedof struct { bool from_stdin}�� fils list��               
		print_usage();
		exit(EXIT_FAILURE);
	}

	if (options->recursive || options->from_stdin)								//options �� recursive(����Լ�) �̰ų� from_stdin�̸�       
		filecnt = FILENAME_CNT;									                //filecent��   �������� FILENAME_CNT = 1024
	else
		filecnt = options->filecnt;									            //�װ� �ƴϸ� filecent�� options

	files = (fileinfo_t*)s_malloc(filecnt * sizeof(fileinfo_t));
	fileidx = 0;

	if (options->from_stdin) {									                //options�� from_stdin�� file list���̸�            
		filename = NULL;
		while ((len = get_line(&filename, &n, stdin)) > 0) {					//(len :size-t ��) len�� filename�� ������ n������ ũ��� stdin���� �����ͼ� �̰� 0���� ũ��  
			if (filename[len - 1] == '\n')
				filename[len - 1] = '\0';									    //filename�� ���� null�̸� �ٹٲ�
			check_add_file(filename);											//���� �߰�
		}
		if (filename != NULL)
			free(filename);
	}

	for (i = 0; i < options->filecnt; i++) {
		filename = options->filenames[i];

		if (stat(filename, &fstats) < 0) {										//filename�� ������ 0���� ������ ���Ͼ��� �ٿ�
			warn("could not stat file: %s", filename);
			continue;
		}
		if (!S_ISDIR(fstats.st_mode)) {											//(S_ISDIR : ���丮 �������� �Ǻ�)
			check_add_file(filename);											//�Ǻ� ���н� ���� �߰�
		}
		else {
			if (!options->recursive) {
				warn("ignoring directory: %s", filename);						//����Լ��� �ƴϸ� ���丮 ���� �˸�         
				continue;
			}
			if (r_opendir(&dir, filename) < 0) {								//���丮 ���� �Լ��� 0���� ������ ���丮 ������ �˸�
				warn("could not open directory: %s", filename);
				continue;
			}
			start = fileidx;													//int start�� fileidx               
			while ((filename = r_readdir(&dir)) != NULL) {						//���丮 �б� �Լ��� filename�̶� ������ ���� �߰�                     
				check_add_file(filename);
				free((void*)filename);
			}
			r_closedir(&dir);													//���丮 �ݱ�   
			if (fileidx - start > 1)
				qsort(files + start, fileidx - start, sizeof(fileinfo_t), fncmp); //qsort(�����ϰ����ϴ� �迭�� ������, �迭�� �� ���ҵ��� �Ѽ�, �迭���� �����ϳ��� ũ��. �񱳸� ������ �Լ� ������)
		}																		//files+start�� ����                        
	}

	if (fileidx == 0) {
		fprintf(stderr, "sxiv: no valid image file given, aborting\n");         //fileidx == 0 �̸� �̹��� ���� �˸�
		exit(EXIT_FAILURE);
	}

	filecnt = fileidx;
	fileidx = options->startnum < filecnt ? options->startnum : 0;				//(startnum : ù ���� �Է¼�) startnum < filecnt startnum�� ������ startnum ũ�� 0 �� ����� fileidx�� �Ѵ�               

	win_init(&win);
	img_init(&img, &win);

	if ((homedir = getenv("XDG_CONFIG_HOME")) == NULL || homedir[0] == '\0') {	//XDG_CONFIG_HOME�� ã�� homedir�� ���ǵǸ�
		homedir = getenv("HOME");												//homdir�ּҰ��� HOME��� ������ ã�� ����                           
		dsuffix = "/.config";													//dsuffix�� �ּҰ��� ./confi��                                          
	}
	if (homedir != NULL) {														//homedir�ּҰ��� NULL�� �ƴϸ�
		char** cmd[] = { &info.cmd, &keyhandler.cmd };							//cmd[]�� ���������Ͱ� &info.cmd, &keyhandler.cmd��
		const char* name[] = { "image-info", "key-handler" };

		for (i = 0; i < ARRLEN(cmd); i++) {
			len = strlen(homedir) + strlen(dsuffix) + strlen(name[i]) + 12;		//len�� ������� homedir, dsuffix, name[i]���Ѱ� + 12
			*cmd[i] = (char*)s_malloc(len);
			snprintf(*cmd[i], len, "%s%s/sxiv/exec/%s", homedir, dsuffix, name[i]);
			if (access(*cmd[i], X_OK) != 0) {									//cmd[]�� �ּҰ��� ���డ�� Ȯ���ϰ� 0�̾ƴϸ� cmd[]�� free���ش�                           
				free(*cmd[i]);
				*cmd[i] = NULL;													//cmd[i]�ּҰ��� NULL   
			}
		}
	}
	else {
		warn("could not locate exec directory");								//������丮 ��ġ���� �ʴٴ� ���                  
	}
	info.fd = -1;

	if (options->thumb_mode) {													//option�� thumb ���� tns �ʱ�ȭ
		mode = MODE_THUMB;
		tns_init(&tns, filecnt, &win);
		while (!tns_load(&tns, 0, &files[0], false, false))
			remove_file(0, false);
		tns.cnt = 1;
	}
	else {																		//�̹�������̸� tns.thumb=NULL�Ҵ� �̹��� �ε�
		mode = MODE_IMAGE;
		tns.thumbs = NULL;
		load_image(fileidx);
	}

	win_open(&win);																//win �����ϰ� run����                     

	run();
	cleanup();

	return 0;
}
