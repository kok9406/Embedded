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

void cleanup(void)                                 //false 값이 아니면 in을 ture로 하고 img를 닫고, 주소 초기화, win 닫고
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

	if (filename == NULL || *filename == '\0')            //파일이름이 없거나 주소안에 아무것도 없을떄
		return;

	if (access(filename, R_OK) < 0) 
	{                  //access : 파일 존재 조사, filename 경로, mode 유무조사 정상시 0, 에러시 -1                              
		warn("could not open file: %s", filename);         //파일이 없을떄임
		return;
	}

	if (fileidx == filecnt) 
	{                        //fileidx가 filent일때 filecnt에 2를 곱하고
		filecnt *= 2;
		files = (fileinfo_t*)s_realloc(files, filecnt * sizeof(fileinfo_t)); //realloc : 동적으로 할당한 메모리의 크기 조절(첫인자 : 이전 동적으로 할당 메모리 주소, 새로 할당할 메모리 크기)
	}                                                         //realloc의 값을 fileinfo_t*으로 cast해서 files로 저장

#if defined _BSD_SOURCE || defined _XOPEN_SOURCE && \                     //BSD_SOURCE, XOPEN_SOURCE, 아무것도 없을경우
	((_XOPEN_SOURCE - 0) >= 500 || defined _XOPEN_SOURCE_EXTENDED)            //XOPEN_SOUCRE - 0 가 500보다 크거나 _XOPEN_SOURCE_EXTENDED 정의됫을경우

		if ((files[fileidx].path = realpath(filename, NULL)) == NULL) 
		{            //files[fileidx]의 path가 절대경로(filename.NULL)이고 이게 NULL이면 realpath가 아니라는 경고
			warn("could not get real path of file: %s\n", filename);
			return;
		}
#else
	if (*filename != '/') 
	{                                          //filename의 주소값이 '/'이 아니면
		if ((files[fileidx].path = absolute_path(filename)) == NULL)
		{         //files[fileidx]의 path가 절대경로이고 이게 NULL이면 절대경로 아니라는 경고를 뛰움
			warn("could not get absolute path of file: %s\n", filename);
			return;
		}
	}
	else 
	{
		files[fileidx].path = NULL;                                    //files[fileidx].path는 NULL이다
	}
#endif

	files[fileidx].loaded = false;                                    //files[fileidx] 로드 실패
	files[fileidx].name = s_strdup(filename);                           //files[fileidx]의 name은 (filename의 길이 + 1)해서 return, s가 없으면 메모리 할당하지 않음( util.c )
	if (files[fileidx].path == NULL)
		files[fileidx].path = files[fileidx].name;                        //   files[fileidx]경로가 NULL이면 files[fileidx]의 name을 (filename의 길이 + 1)해서 return, s가 없으면 메모리 할당하지 않음( util.c )
	if ((bn = strrchr(files[fileidx].name, '/')) != NULL && bn[1] != '\0')      // bn( files[fileidx].name의 마지막에 '/'이 있으면 그 주소를 반환)이 NULL 아니고 bn[1]이 NULL이 아니면
		files[fileidx].base = ++bn;                                    //files[fileidx].base = ++bn;   
	else
		files[fileidx].base = files[fileidx].name;                        //files[fileidx].base = files[fileidx].name이다.                              
	fileidx++;
}

void remove_file(int n, bool manual)                                 //파일 제거   ( bool : ture , false 저장         )               
{
	if (n < 0 || n >= filecnt)
		return;

	if (filecnt == 1) 
	{
		if (!manual)
			fprintf(stderr, "sxiv: no more files to display, aborting\n");         //filecnt == 1 이고 manual이 아니면 파일 없음 알림         
		cleanup();
		exit(manual ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	if (files[n].path != files[n].name)                                    //files[n].path != files[n].name 이면 둘다 free 시킴
	{
		free((void*)files[n].path);
		free((void*)files[n].name);
	}

	if (n + 1 < filecnt)
		memmove(files + n, files + n + 1, (filecnt - n - 1) * sizeof(fileinfo_t));   //memove:(복사되는 메모리의 첫번쨰 주소, 복사할 메모리의 첫번쨰 주소,복사할크기)
	if (n + 1 < tns.cnt) 
	{
		memmove(tns.thumbs + n, tns.thumbs + n + 1, (tns.cnt - n - 1) * sizeof(thumb_t));       //memove:(복사되는 메모리의 첫번쨰 주소, 복사할 메모리의 첫번쨰 주소,복사할크기)
		memset(tns.thumbs + tns.cnt - 1, 0, sizeof(thumb_t));                           //memset : (셋팅할 메모리블럭의 첫주소, 세팅할 값, 세팅할 메모의 블럭의 크기)      
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

void open_info(void)                                                //open 정보
{
	static pid_t pid;
	int pfd[2];

	if (info.cmd == NULL || info.open || win.bar.h == 0)                     //info라는 구조체 값이 (info.cmd == NULL || info.open || win.bar.h == 0)         
		return;
	if (info.fd != -1) 
	{                                             //info.fd != -1이면 close(info.fd
		close(info.fd);                                                //info.fd를 닫는다      
		kill(pid, SIGTERM);                                             //SIGTERM : Software termination signal from kill               
		info.fd = -1;
	}
	win.bar.l[0] = '\0';

	if (pipe(pfd) < 0)
		return;
	pid = fork();                                                   //pid 가 fork()이면         
	if (pid > 0) 
	{                                                   //parent 동작            
		close(pfd[1]);                                                //pfd[1]을 닫고 pfd[0]의 특성을 변경
		fcntl(pfd[0], F_SETFL, O_NONBLOCK);                                 //fcntl : (제어할 파일의  파일 기술자, 파일 기술자에 대한 특성을 제어하는 매개변수, 두번쨰인자에 의해 결정되는 선택적인 값)
		info.fd = pfd[0];                                             //info.fd = pfd[0] 하고 , info.open을 참으로
		info.i = info.lastsep = 0;
		info.open = true;
	}
	else if (pid == 0) 
	{                                             //children 동작
		close(pfd[0]);                                                //pfd[0]을 닫고, 
		dup2(pfd[1], 1);
		execl(info.cmd, info.cmd, files[fileidx].name, NULL);                  //info.cmd에 지정된 경로의 파일을 실행                        
		warn("could not exec: %s", info.cmd);
		exit(EXIT_FAILURE);
	}
}

void read_info(void)                                                //read 정보 (읽어들인 정보 n 이 0보다 커야 동작)                                             
{
	ssize_t i, n;
	char buf[BAR_L_LEN];

	while (true) 
	{
		n = read(info.fd, buf, sizeof(buf));                              //n에 buf의 값을 info.fd로 읽어 들임               
		if (n < 0 && errno == EAGAIN)                                    //n 값이 0보다 작거나 errno라는 주소가 에러코드이면
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
	if (new < 0 || new >= filecnt)                                      //new가 0보다크고 filecent보다 작아야함
		return;

	win_set_cursor(&win, CURSOR_WATCH);                                //커서관련 코딩임     
	reset_timeout(slideshow);

	if (new != fileidx)
		alternate = fileidx;

	img_close(&img, false);                                    //image.c에 잇는데 해석 불가                                             
	while (!img_load(&img, &files[new])) 
	{                        //!img_load실패시 파일삭제
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

void update_info(void)                                                      //update 정보
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
		win_set_title(&win, "sxiv");                                             //thumb모드시 sxiv로 디스플레이 타이틀 지정
	}
	else 
	{
		snprintf(title, sizeof(title), "sxiv - %s", files[sel].name);                  //title에 files[sel].name를 title 사이즈로 복사
		win_set_title(&win, title);                                             //title로 디스플레이 타이틀 지정                                       
	}

	/* update bar contents */
	if (win.bar.h == 0)
		return;
	mark = files[sel].marked ? "* " : "";
	if (mode == MODE_THUMB) 
	{                                                //thumb시 mark
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
	else {                                                         //image 모드
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
	{                                                      //text 창에  text 뛰움
		fn = strlen(files[sel].name);
		if (fn < llen &&
			win_textwidth(files[sel].name, fn, true) +
			win_textwidth(rt, n, true) < win.w)
		{
			strncpy(lt, files[sel].name, llen);                                           //lt에 files[sel].name을 llen 길이로 복사
		}
		else 
		{
			strncpy(lt, files[sel].base, llen);
		}
	}
}

void redraw(void)                                          //이미지 만드는 함수 가틈         
{
	int t;

	if (mode == MODE_IMAGE) 
	{
		img_render(&img);                                    //이미지 모드일때 이미지 제작
		if (img.ss.on) 
		{
			t = img.ss.delay * 1000;
			if (img.multi.cnt > 0 && img.multi.animate)
				t = MAX(t, img.multi.length);                           //t 랑 img.multi.length를 비교해서 t에 넣는다
			set_timeout(slideshow, t, false);
		}
	}
	else
	{                                             //thumb모드일때 이미지 제작      
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
	{                                    //이미지 모드에서 커서 리셋                     
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
	else {                                                //thumbs 모드에서 커서 리셋            
		if (tns.cnt != filecnt)
			cursor = CURSOR_WATCH;
		else
			cursor = CURSOR_ARROW;
	}
	win_set_cursor(&win, cursor);                                 //커서 윈도우에 뛰우기               
}

void animate(void)
{
	if (img_frame_animate(&img, false)) 
	{                           //img에 frame 제작 생기를 불어넣는다
		redraw();
		set_timeout(animate, img.multi.frames[img.multi.sel].delay, true);
	}
}

void slideshow(void)
{
	load_image(fileidx + 1 < filecnt ? fileidx + 1 : 0);               //0과 filedix + 1을 비교해서 fileidx + 1 값을 로드이미지하고 redraw

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
	{											    //keyhandler.cmd  없으면 경고
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
		mask & ShiftMask ? "S-" : "", key);										//mask한 주소 controal mask, mod1mask, shiftmask를 kstr의 사이즈에 맞게 kstr에 저장

	stat(files[n].path, &oldst);												//oldst의 값을 files[n]의 경로로 읽어옴                           

	if ((pid = fork()) == 0)
	{													//children process 동작                  
		execl(keyhandler.cmd, keyhandler.cmd, kstr, files[n].path, NULL);
		warn("could not exec key handler");
		exit(EXIT_FAILURE);
	}
	else if (pid < 0)
	{															//children process 동작 에러시
		warn("could not fork key handler");
		return;
	}
	win_set_cursor(&win, CURSOR_WATCH);											//win창에 커서 세팅            

	waitpid(pid, &status, 0);													//waitpid : ( wait할 자식 프로세스 유형 0보다 크면 wait , 자식의 상태 나타냄 , 0이면 return 할떄까지 block)
	retval = WEXITSTATUS(status);												//(WEXITSTATUS( status) : 자식 프로세스가 정상 종료되었을 때 반환한 값) retval에 반환값을 넣는다
	if (WIFEXITED(status) == 0 || retval != 0)									//(WIFEXITED( status) : 자식 프로세스가 정상적으로 종료되었다면 TRUE)   즉 자식이 정상종료 되엇다면
		warn("key handler exited with non-zero return value: %d", retval);

	if (stat(files[n].path, &newst) == 0 &&										//newst의 내용을 files[n]의 경로로 읽어온것이 0이고      &oldst.st_mtime, &newst.st_mtime를 비교해서 같으면                        
		memcmp(&oldst.st_mtime, &newst.st_mtime, sizeof(oldst.st_mtime)) == 0)
	{
		/* file has not changed */
		win_set_cursor(&win, CURSOR_ARROW);										//파일은 변화지 않앗으므로 커서만들고 시간설정하고 등등   
		set_timeout(reset_cursor, TO_CURSOR_HIDE, true);
		return;
	}
	if (mode == MODE_IMAGE)
	{
		img_close(&img, true);													//이미지 모드면 이미지 종류하고 fileidx이미지 로드               
		load_image(fileidx);
	}
	if (!tns_load(&tns, n, &files[n], true, mode == MODE_IMAGE) &&				//thumb 모드일대
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

void on_keypress(XKeyEvent * kev)												//key입력에 관해 (필요없음)
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
		prefix = prefix * 10 + (int)(key - '0');								//숫자 명령에 대한
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

void on_buttonpress(XButtonEvent * bev)											//마우스 버튼 입력에 관해 (필요없음)9
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

void run(void)																	//input값을 확인하고 그에 맞는 이벤트를 실행하는 함수, 모드에 맞는 이벤트 (keypass,커서)이런것 실행                     
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
			/* load thumbnails */												//thumbnail 로드하고 tns_load되면 tns.cnt 증가            
			set_timeout(redraw, TO_REDRAW_THUMBS, false);
			if (tns_load(&tns, tns.cnt, &files[tns.cnt], false, false)) {
				tns.cnt++;
			}
			else {
				remove_file(tns.cnt, false);									//tns_load 안될시 파일 삭제   
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
			/* check for timeouts & input */									//input 확인   fds값들을 확인하여 적절하면 read_info 실행
			xfd = ConnectionNumber(win.env.dpy);
			FD_ZERO(&fds);														//fds내용의 모든 비트 삭제
			FD_SET(xfd, &fds);													//fds내용중 xfd에 해당하는 비트 1로                        
			if (info.fd != -1) {
				FD_SET(info.fd, &fds);											//info.fd가 -1이 아니면 fds내용중 info.fd을 찾고                        
				xfd = MAX(xfd, info.fd);										//xfd를 info.fd중 최고를 xfd로 뽑아낸다
			}
			select(xfd + 1, &fds, 0, 0, to_set ? &timeout : NULL);				//select함수 : (검사하고 하는 소켓 +1, 읽기셋 주소, 쓰기셋 주소, 예외셋 주소,타임아웃시간설정)         
			if (info.fd != -1 && FD_ISSET(info.fd, &fds))
				read_info();
		}

		do {																	//Xlib : c프로그래밍 언어로 작성된 x 윈동 시스템 프로토콜 크라이언트 라이블러리
			XNextEvent(win.env.dpy, &ev);										//이벤트 생기기를 기다리고 있다 , 이벤트가 시작되면 아랫줄로가고 어떤 이벤트인지 식별하는 기능   
			discard = false;
			if (XEventsQueued(win.env.dpy, QueuedAlready) > 0) {				//이벤트들중 이벤트를 골라 낸다
				XPeekEvent(win.env.dpy, &nextev);
				switch (ev.type) {
				case ConfigureNotify:											//창상태가 바뀔때                        
					discard = ev.type == nextev.type;
					break;
				case KeyPress:													//키가 눌릴때
					discard = (nextev.type == KeyPress || nextev.type == KeyRelease) && ev.xkey.keycode == nextev.xkey.keycode;
					break;
				}
			}
		} while (discard);

		switch (ev.type) {
			/* handle events */													//이벤트 handle                  
		case ButtonPress:														//버튼이 눌린경우 버튼press함수
			on_buttonpress(&ev.xbutton);
			break;
		case ClientMessage:														//다른 클라이언트가 메세지를 보내왔을떄         
			if ((Atom)ev.xclient.data.l[0] == atoms[ATOM_WM_DELETE_WINDOW])
				return;
			break;
		case ConfigureNotify:													//창의 상태가 바뀌었을떄                  
			if (win_configure(&win, &ev.xconfigure)) {							//이미지의 구성을보고 이미지모드와 thumbs모드 구별
				if (mode == MODE_IMAGE) {
					img.dirty = true;
					img.checkpan = true;
				}
				else {
					tns.dirty = true;
				}
				if (!resized || win.fullscreen) {								//모드에 맞게 resize해서 redraw      
					redraw();
					set_timeout(clear_resize, TO_REDRAW_RESIZE, false);
					resized = true;
				}
				else {
					set_timeout(redraw, TO_REDRAW_RESIZE, false);
				}
			}
			break;
		case Expose:															//win창에 표현         
			win_expose(&win, &ev.xexpose);
			break;
		case KeyPress:															//키입력               
			on_keypress(&ev.xkey);
			break;
		case MotionNotify:														//동작 알림을 이미지모드일경우 win에 커서 만듬         
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
	return strcoll(((fileinfo_t*)a)->name, ((fileinfo_t*)b)->name);				//(fileinfo_t*) a)->name와 ((fileinfo_t*) b)->name를 다른것이 나타날때까지 비교
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

	parse_options(argc, argv);									                //Command option을 준다 (명령어 같은거 예를들어 d는 뭐다 이런식 ) 

	if (options->clean_cache) {									                //option이 clean_cache면 thumbs 초기화,캐시도 초기화
		tns_init(&tns, 0, NULL);
		tns_clean_cache(&tns);
		exit(EXIT_SUCCESS);
	}

	if (options->filecnt == 0 && !options->from_stdin) {						//from_stdion : typedof struct { bool from_stdin}인 fils list임               
		print_usage();
		exit(EXIT_FAILURE);
	}

	if (options->recursive || options->from_stdin)								//options 가 recursive(재귀함수) 이거나 from_stdin이면       
		filecnt = FILENAME_CNT;									                //filecent가   열거형인 FILENAME_CNT = 1024
	else
		filecnt = options->filecnt;									            //그게 아니면 filecent가 options

	files = (fileinfo_t*)s_malloc(filecnt * sizeof(fileinfo_t));
	fileidx = 0;

	if (options->from_stdin) {									                //options가 from_stdin인 file list형이면            
		filename = NULL;
		while ((len = get_line(&filename, &n, stdin)) > 0) {					//(len :size-t 형) len이 filename의 내용이 n내용의 크기로 stdin에서 가져와서 이게 0보다 크면  
			if (filename[len - 1] == '\n')
				filename[len - 1] = '\0';									    //filename의 열이 null이면 줄바꿈
			check_add_file(filename);											//파일 추가
		}
		if (filename != NULL)
			free(filename);
	}

	for (i = 0; i < options->filecnt; i++) {
		filename = options->filenames[i];

		if (stat(filename, &fstats) < 0) {										//filename의 정보가 0보다 작으면 파일없음 뛰움
			warn("could not stat file: %s", filename);
			continue;
		}
		if (!S_ISDIR(fstats.st_mode)) {											//(S_ISDIR : 디렉토리 파일인지 판별)
			check_add_file(filename);											//판별 실패시 파일 추가
		}
		else {
			if (!options->recursive) {
				warn("ignoring directory: %s", filename);						//재귀함수가 아니면 디렉토리 무시 알림         
				continue;
			}
			if (r_opendir(&dir, filename) < 0) {								//디렉토리 열기 함수가 0보다 작으면 디렉토리 못연다 알림
				warn("could not open directory: %s", filename);
				continue;
			}
			start = fileidx;													//int start가 fileidx               
			while ((filename = r_readdir(&dir)) != NULL) {						//디렉토리 읽기 함수가 filename이랑 같은면 파일 추가                     
				check_add_file(filename);
				free((void*)filename);
			}
			r_closedir(&dir);													//디렉토리 닫기   
			if (fileidx - start > 1)
				qsort(files + start, fileidx - start, sizeof(fileinfo_t), fncmp); //qsort(정렬하고자하는 배열의 포인터, 배열의 각 원소들의 총수, 배열에서 원소하나의 크기. 비교를 수행할 함수 포인터)
		}																		//files+start를 정렬                        
	}

	if (fileidx == 0) {
		fprintf(stderr, "sxiv: no valid image file given, aborting\n");         //fileidx == 0 이면 이미지 없다 알림
		exit(EXIT_FAILURE);
	}

	filecnt = fileidx;
	fileidx = options->startnum < filecnt ? options->startnum : 0;				//(startnum : 첫 시작 입력수) startnum < filecnt startnum이 작으면 startnum 크면 0 이 결과를 fileidx로 한다               

	win_init(&win);
	img_init(&img, &win);

	if ((homedir = getenv("XDG_CONFIG_HOME")) == NULL || homedir[0] == '\0') {	//XDG_CONFIG_HOME을 찾아 homedir로 정의되면
		homedir = getenv("HOME");												//homdir주소값을 HOME라는 변수를 찾아 지정                           
		dsuffix = "/.config";													//dsuffix의 주소값을 ./confiㅎ                                          
	}
	if (homedir != NULL) {														//homedir주소값이 NULL이 아니면
		char** cmd[] = { &info.cmd, &keyhandler.cmd };							//cmd[]의 이중포인터가 &info.cmd, &keyhandler.cmd면
		const char* name[] = { "image-info", "key-handler" };

		for (i = 0; i < ARRLEN(cmd); i++) {
			len = strlen(homedir) + strlen(dsuffix) + strlen(name[i]) + 12;		//len의 사이즈는 homedir, dsuffix, name[i]더한거 + 12
			*cmd[i] = (char*)s_malloc(len);
			snprintf(*cmd[i], len, "%s%s/sxiv/exec/%s", homedir, dsuffix, name[i]);
			if (access(*cmd[i], X_OK) != 0) {									//cmd[]의 주소값을 실행가능 확인하고 0이아니면 cmd[]를 free해준다                           
				free(*cmd[i]);
				*cmd[i] = NULL;													//cmd[i]주소값을 NULL   
			}
		}
	}
	else {
		warn("could not locate exec directory");								//실행디렉토리 위치하지 않다는 경고                  
	}
	info.fd = -1;

	if (options->thumb_mode) {													//option이 thumb 모드면 tns 초기화
		mode = MODE_THUMB;
		tns_init(&tns, filecnt, &win);
		while (!tns_load(&tns, 0, &files[0], false, false))
			remove_file(0, false);
		tns.cnt = 1;
	}
	else {																		//이미지모드이면 tns.thumb=NULL할당 이미지 로드
		mode = MODE_IMAGE;
		tns.thumbs = NULL;
		load_image(fileidx);
	}

	win_open(&win);																//win 시작하고 run실행                     

	run();
	cleanup();

	return 0;
}
