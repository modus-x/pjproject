/* $Id$ */
/*
 * Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <pjmedia-videodev/videodev_imp.h>
#include <pjmedia/clock.h>
#include <pj/assert.h>
#include <pj/log.h>
#include <pj/os.h>
#include <pj/rand.h>
#include <windows.h>

#define flipBits(n, b) ((n) ^ ((1u << (b)) - 1))

#if defined(PJMEDIA_HAS_VIDEO) && PJMEDIA_HAS_VIDEO != 0 && \
    defined(PJMEDIA_VIDEO_DEV_HAS_DESKTOP_SRC) &&           \
    PJMEDIA_VIDEO_DEV_HAS_DESKTOP_SRC != 0

#define THIS_FILE "desktop_dev.c"


#define DEFAULT_CLOCK_RATE 90000
#define DEFAULT_WIDTH 1920
#define DEFAULT_HEIGHT 1080
#define DEFAULT_FPS 25

/* desktop_ device info */
struct desktop_dev_info
{
    pjmedia_vid_dev_info info;
};

/* desktop_ factory */
struct desktop_factory
{
    pjmedia_vid_dev_factory base;
    pj_pool_t *pool;
    pj_pool_factory *pf;

    unsigned dev_count;
    struct desktop_dev_info *dev_info;
};

struct desktop_fmt_info
{
    pjmedia_format_id fmt_id; /* Format ID                */
};

static struct desktop_fmt_info desktop_fmts[] =
    {
        {PJMEDIA_FORMAT_BGRA},
};

/* Video stream. */
struct desktop_stream
{
    pjmedia_vid_dev_stream base; /**< Base stream	    */
    pjmedia_vid_dev_param param; /**< Settings	    */
    pj_pool_t *pool;             /**< Memory pool.       */

    pjmedia_vid_dev_cb vid_cb; /**< Stream callback.   */
    void *user_data;           /**< Application data.  */

    const struct desktop_fmt_info *dfi;
    const pjmedia_video_format_info *vfi;
    pjmedia_video_apply_fmt_param vafp;
    pj_uint8_t *first_line[PJMEDIA_MAX_VIDEO_PLANES];
    pj_timestamp ts;
    unsigned ts_inc;

    /* For active capturer only */
    pjmedia_clock *clock;
    pj_uint8_t *clock_buf;
};

/* Prototypes */
static pj_status_t desktop_factory_init(pjmedia_vid_dev_factory *f);
static pj_status_t desktop_factory_destroy(pjmedia_vid_dev_factory *f);
static pj_status_t desktop_factory_refresh(pjmedia_vid_dev_factory *f);
static unsigned desktop_factory_get_dev_count(pjmedia_vid_dev_factory *f);
static pj_status_t desktop_factory_get_dev_info(pjmedia_vid_dev_factory *f,
                                                unsigned index,
                                                pjmedia_vid_dev_info *info);
static pj_status_t desktop_factory_default_param(pj_pool_t *pool,
                                                 pjmedia_vid_dev_factory *f,
                                                 unsigned index,
                                                 pjmedia_vid_dev_param *param);
static pj_status_t desktop_factory_create_stream(
    pjmedia_vid_dev_factory *f,
    pjmedia_vid_dev_param *param,
    const pjmedia_vid_dev_cb *cb,
    void *user_data,
    pjmedia_vid_dev_stream **p_vid_strm);

static pj_status_t desktop_stream_get_param(pjmedia_vid_dev_stream *strm,
                                            pjmedia_vid_dev_param *param);
static pj_status_t desktop_stream_get_cap(pjmedia_vid_dev_stream *strm,
                                          pjmedia_vid_dev_cap cap,
                                          void *value);
static pj_status_t desktop_stream_set_cap(pjmedia_vid_dev_stream *strm,
                                          pjmedia_vid_dev_cap cap,
                                          const void *value);
static pj_status_t desktop_stream_get_frame(pjmedia_vid_dev_stream *strm,
                                            pjmedia_frame *frame);
static pj_status_t desktop_stream_start(pjmedia_vid_dev_stream *strm);
static pj_status_t desktop_stream_stop(pjmedia_vid_dev_stream *strm);
static pj_status_t desktop_stream_destroy(pjmedia_vid_dev_stream *strm);

/* Operations */
static pjmedia_vid_dev_factory_op factory_op =
    {
        &desktop_factory_init,
        &desktop_factory_destroy,
        &desktop_factory_get_dev_count,
        &desktop_factory_get_dev_info,
        &desktop_factory_default_param,
        &desktop_factory_create_stream,
        &desktop_factory_refresh};

static pjmedia_vid_dev_stream_op stream_op =
    {
        &desktop_stream_get_param,
        &desktop_stream_get_cap,
        &desktop_stream_set_cap,
        &desktop_stream_start,
        &desktop_stream_get_frame,
        NULL,
        &desktop_stream_stop,
        &desktop_stream_destroy};

/****************************************************************************
 * Factory operations
 */
/*
 * Init desktop_ video driver.
 */
pjmedia_vid_dev_factory *pjmedia_desktop_factory(pj_pool_factory *pf)
{
    struct desktop_factory *f;
    pj_pool_t *pool;

    pool = pj_pool_create(pf, "desktop video", 512, 512, NULL);
    f = PJ_POOL_ZALLOC_T(pool, struct desktop_factory);
    f->pf = pf;
    f->pool = pool;
    f->base.op = &factory_op;

    return &f->base;
}

/* API: init factory */
static pj_status_t desktop_factory_init(pjmedia_vid_dev_factory *f)
{
    struct desktop_factory *cf = (struct desktop_factory *)f;
    struct desktop_dev_info *ddi;
    unsigned i;

    cf->dev_count = 2;

    cf->dev_info = (struct desktop_dev_info *)
        pj_pool_calloc(cf->pool, cf->dev_count,
                       sizeof(struct desktop_dev_info));

    /* Passive capturer */
    ddi = &cf->dev_info[0];
    pj_bzero(ddi, sizeof(*ddi));
    pj_ansi_strncpy(ddi->info.name, "Desktop passive capture",
                    sizeof(ddi->info.name));
    ddi->info.driver[sizeof(ddi->info.driver) - 1] = '\0';
    pj_ansi_strncpy(ddi->info.driver, "GDI", sizeof(ddi->info.driver));
    ddi->info.driver[sizeof(ddi->info.driver) - 1] = '\0';
    ddi->info.dir = PJMEDIA_DIR_CAPTURE;
    ddi->info.has_callback = PJ_FALSE;

    ddi->info.caps = PJMEDIA_VID_DEV_CAP_FORMAT;
    ddi->info.fmt_cnt = sizeof(desktop_fmts) / sizeof(desktop_fmts[0]);
    for (i = 0; i < ddi->info.fmt_cnt; i++)
    {
        pjmedia_format *fmt = &ddi->info.fmt[i];
        pjmedia_format_init_video(fmt, desktop_fmts[i].fmt_id,
                                  DEFAULT_WIDTH, DEFAULT_HEIGHT,
                                  DEFAULT_FPS, 1);
    }

    /* Active capturer */
    ddi = &cf->dev_info[1];
    pj_bzero(ddi, sizeof(*ddi));
    pj_ansi_strncpy(ddi->info.name, "Desktop active capture",
                    sizeof(ddi->info.name));
    ddi->info.driver[sizeof(ddi->info.driver) - 1] = '\0';
    pj_ansi_strncpy(ddi->info.driver, "GDI", sizeof(ddi->info.driver));
    ddi->info.driver[sizeof(ddi->info.driver) - 1] = '\0';
    ddi->info.dir = PJMEDIA_DIR_CAPTURE;
    ddi->info.has_callback = PJ_TRUE;

    ddi->info.caps = PJMEDIA_VID_DEV_CAP_FORMAT;
    ddi->info.fmt_cnt = sizeof(desktop_fmts) / sizeof(desktop_fmts[0]);
    for (i = 0; i < ddi->info.fmt_cnt; i++)
    {
        pjmedia_format *fmt = &ddi->info.fmt[i];
        pjmedia_format_init_video(fmt, desktop_fmts[i].fmt_id,
                                  DEFAULT_WIDTH, DEFAULT_HEIGHT,
                                  DEFAULT_FPS, 1);
    }

    PJ_LOG(4, (THIS_FILE, "Desktop capture initialized with %d device(s):",
               cf->dev_count));
    for (i = 0; i < cf->dev_count; i++)
    {
        PJ_LOG(4, (THIS_FILE, "%2d: %s", i, cf->dev_info[i].info.name));
    }

    return PJ_SUCCESS;
}

/* API: destroy factory */
static pj_status_t desktop_factory_destroy(pjmedia_vid_dev_factory *f)
{
    struct desktop_factory *cf = (struct desktop_factory *)f;

    pj_pool_safe_release(&cf->pool);

    return PJ_SUCCESS;
}

/* API: refresh the list of devices */
static pj_status_t desktop_factory_refresh(pjmedia_vid_dev_factory *f)
{
    PJ_UNUSED_ARG(f);
    return PJ_SUCCESS;
}

/* API: get number of devices */
static unsigned desktop_factory_get_dev_count(pjmedia_vid_dev_factory *f)
{
    struct desktop_factory *cf = (struct desktop_factory *)f;
    return cf->dev_count;
}

/* API: get device info */
static pj_status_t desktop_factory_get_dev_info(pjmedia_vid_dev_factory *f,
                                                unsigned index,
                                                pjmedia_vid_dev_info *info)
{
    struct desktop_factory *cf = (struct desktop_factory *)f;

    PJ_ASSERT_RETURN(index < cf->dev_count, PJMEDIA_EVID_INVDEV);

    pj_memcpy(info, &cf->dev_info[index].info, sizeof(*info));

    return PJ_SUCCESS;
}

/* API: create default device parameter */
static pj_status_t desktop_factory_default_param(pj_pool_t *pool,
                                                 pjmedia_vid_dev_factory *f,
                                                 unsigned index,
                                                 pjmedia_vid_dev_param *param)
{
    struct desktop_factory *cf = (struct desktop_factory *)f;
    struct desktop_dev_info *di = &cf->dev_info[index];

    PJ_ASSERT_RETURN(index < cf->dev_count, PJMEDIA_EVID_INVDEV);

    PJ_UNUSED_ARG(pool);

    pj_bzero(param, sizeof(*param));
    param->dir = PJMEDIA_DIR_CAPTURE;
    param->cap_id = index;
    param->rend_id = PJMEDIA_VID_INVALID_DEV;
    param->flags = PJMEDIA_VID_DEV_CAP_FORMAT;
    param->clock_rate = DEFAULT_CLOCK_RATE;
    pj_memcpy(&param->fmt, &di->info.fmt[0], sizeof(param->fmt));

    return PJ_SUCCESS;
}

static const struct desktop_fmt_info *get_desktop_fmt_info(pjmedia_format_id id)
{
    unsigned i;

    for (i = 0; i < sizeof(desktop_fmts) / sizeof(desktop_fmts[0]); i++)
    {
        if (desktop_fmts[i].fmt_id == id)
            return &desktop_fmts[i];
    }

    return NULL;
}

static pj_status_t capture(pjmedia_frame *frame, struct desktop_stream *stream)
{
    HWND hwnd = NULL;
    HDC hdcWindow;
    HDC hdcMemDC = NULL;
    HBITMAP hbmp = NULL;
    int x = 0, y = 0;

    pj_uint8_t *ptr = frame->buf;

    BYTE* lpbitmap = NULL;
    HANDLE hDIB = NULL;

    // Retrieve the handle to a display device context for the client
    // area of the window.
    hdcWindow = GetDC(hwnd);

    // Create a compatible DC, which is used in a BitBlt from the window DC.
    hdcMemDC = CreateCompatibleDC(hdcWindow);

    if (!hdcMemDC)
    {
        PJ_LOG(1, (THIS_FILE, "CreateCompatibleDC has failed"));
        goto done;
    }

    // Get the client area for size calculation.
    if (hwnd == NULL)
    {
        x = GetSystemMetrics(SM_CXSCREEN);
        y = GetSystemMetrics(SM_CYSCREEN);
    }
    else
    {
        RECT rcClient;
        GetClientRect(hwnd, &rcClient);
        x = rcClient.right - rcClient.left;
        y = rcClient.bottom - rcClient.top;
    }

    DWORD dwBmpSize = stream->vafp.size.w * stream->vafp.size.h * 4;

    hDIB = GlobalAlloc(GHND, dwBmpSize);
    lpbitmap = (BYTE*)GlobalLock(hDIB);

    // Create a bitmap from the Window DC.
    BITMAPV4HEADER bmpheader;
    int height = (pj_int16_t)stream->vafp.size.h;
    memset(&bmpheader, 0, sizeof(BITMAPV4HEADER));
    bmpheader.bV4Size = sizeof(BITMAPV4HEADER);
    bmpheader.bV4Width = stream->vafp.size.w;
    bmpheader.bV4Height = -height;
    bmpheader.bV4Planes = 1;
    bmpheader.bV4BitCount = 32;
    bmpheader.bV4V4Compression = BI_BITFIELDS;
    bmpheader.bV4SizeImage = dwBmpSize;
    bmpheader.bV4RedMask = 0x00FF0000;
    bmpheader.bV4GreenMask = 0x0000FF00;
    bmpheader.bV4BlueMask = 0x000000FF;
    bmpheader.bV4AlphaMask = 0xFF000000;
    bmpheader.bV4CSType = 0x57696e20; // LCS_WINDOWS_COLOR_SPACE
    hbmp = CreateDIBSection(hdcWindow, (BITMAPINFO*)(&bmpheader), DIB_RGB_COLORS, (void**)&lpbitmap, NULL, 0);

    if (!hbmp)
    {
        PJ_LOG(1, (THIS_FILE, "CreateCompatibleBitmap has failed"));
        goto done;
    }

    // Select the compatible bitmap into the compatible memory DC.
    SelectObject(hdcMemDC, hbmp);

    // Bit block transfer into our compatible memory DC.
    if (!BitBlt(hdcMemDC,
                    0, 0,
                    stream->vafp.size.w,
                    stream->vafp.size.h,
                    hdcWindow,
                    0, 0,
                    SRCCOPY))
    {
        PJ_LOG(1, (THIS_FILE, "StretchBlt has failed"));
        goto done;
    }

    memcpy(ptr, lpbitmap, dwBmpSize);

    GlobalUnlock(hDIB);
    GlobalFree(hDIB);

done:
    DeleteObject(hbmp);
    DeleteObject(hdcMemDC);
    ReleaseDC(hwnd, hdcWindow);
    return PJ_SUCCESS;
}

static void clock_cb(const pj_timestamp *ts, void *user_data)
{
    struct desktop_stream *stream = (struct desktop_stream *)user_data;
    pjmedia_frame f;
    pj_status_t status;

    PJ_UNUSED_ARG(ts);

    pj_bzero(&f, sizeof(f));
    f.buf = stream->clock_buf;
    f.size = stream->vafp.framebytes;
    status = desktop_stream_get_frame(&stream->base, &f);
    if (status == PJ_SUCCESS)
    {
        (*stream->vid_cb.capture_cb)(&stream->base, stream->user_data, &f);
    }
}

/* API: create stream */
static pj_status_t desktop_factory_create_stream(
    pjmedia_vid_dev_factory *f,
    pjmedia_vid_dev_param *param,
    const pjmedia_vid_dev_cb *cb,
    void *user_data,
    pjmedia_vid_dev_stream **p_vid_strm)
{
    struct desktop_factory *cf = (struct desktop_factory *)f;
    pj_pool_t *pool;
    struct desktop_stream *strm;
    const pjmedia_video_format_detail *vfd;
    const pjmedia_video_format_info *vfi;
    pjmedia_video_apply_fmt_param vafp;
    const struct desktop_fmt_info *dfi;
    unsigned i;

    PJ_ASSERT_RETURN(f && param && p_vid_strm, PJ_EINVAL);
    PJ_ASSERT_RETURN(param->fmt.type == PJMEDIA_TYPE_VIDEO &&
                         param->fmt.detail_type == PJMEDIA_FORMAT_DETAIL_VIDEO &&
                         param->dir == PJMEDIA_DIR_CAPTURE,
                     PJ_EINVAL);

    pj_bzero(&vafp, sizeof(vafp));

    vfd = pjmedia_format_get_video_format_detail(&param->fmt, PJ_TRUE);
    vfi = pjmedia_get_video_format_info(NULL, param->fmt.id);
    dfi = get_desktop_fmt_info(param->fmt.id);
    if (!vfi || !dfi)
        return PJMEDIA_EVID_BADFORMAT;

    vafp.size = param->fmt.det.vid.size;
    if (vfi->apply_fmt(vfi, &vafp) != PJ_SUCCESS)
        return PJMEDIA_EVID_BADFORMAT;

    /* Create and Initialize stream descriptor */
    pool = pj_pool_create(cf->pf, "desktop-dev", 512, 512, NULL);
    PJ_ASSERT_RETURN(pool != NULL, PJ_ENOMEM);

    strm = PJ_POOL_ZALLOC_T(pool, struct desktop_stream);
    pj_memcpy(&strm->param, param, sizeof(*param));
    strm->pool = pool;
    pj_memcpy(&strm->vid_cb, cb, sizeof(*cb));
    strm->user_data = user_data;
    strm->vfi = vfi;
    strm->dfi = dfi;
    pj_memcpy(&strm->vafp, &vafp, sizeof(vafp));
    strm->ts_inc = PJMEDIA_SPF2(param->clock_rate, &vfd->fps, 1);

    for (i = 0; i < vfi->plane_cnt; ++i)
    {
        strm->first_line[i] = pj_pool_alloc(pool, vafp.strides[i]);
        pj_memset(strm->first_line[i], 255, vafp.strides[i]);
    }

    /* Active role? */
    if (param->cap_id == 1 && cb && cb->capture_cb)
    {
        pjmedia_clock_param clock_param;
        pj_status_t status;

        /* Allocate buffer */
        strm->clock_buf = pj_pool_alloc(pool, strm->vafp.framebytes);

        /* Create clock */
        pj_bzero(&clock_param, sizeof(clock_param));
        clock_param.usec_interval = PJMEDIA_PTIME(&vfd->fps);
        clock_param.clock_rate = param->clock_rate;
        status = pjmedia_clock_create2(pool, &clock_param,
                                       PJMEDIA_CLOCK_NO_HIGHEST_PRIO,
                                       &clock_cb,
                                       strm, &strm->clock);
        if (status != PJ_SUCCESS)
        {
            pj_pool_release(pool);
            return status;
        }
    }

    /* Done */
    strm->base.op = &stream_op;
    *p_vid_strm = &strm->base;

    return PJ_SUCCESS;
}

/* API: Get stream info. */
static pj_status_t desktop_stream_get_param(pjmedia_vid_dev_stream *s,
                                            pjmedia_vid_dev_param *pi)
{
    struct desktop_stream *strm = (struct desktop_stream *)s;

    PJ_ASSERT_RETURN(strm && pi, PJ_EINVAL);

    pj_memcpy(pi, &strm->param, sizeof(*pi));

    /*    if (desktop_stream_get_cap(s, PJMEDIA_VID_DEV_CAP_INPUT_SCALE,
                                &pi->fmt.info_size) == PJ_SUCCESS)
        {
            pi->flags |= PJMEDIA_VID_DEV_CAP_INPUT_SCALE;
        }
    */
    return PJ_SUCCESS;
}

/* API: get capability */
static pj_status_t desktop_stream_get_cap(pjmedia_vid_dev_stream *s,
                                          pjmedia_vid_dev_cap cap,
                                          void *pval)
{
    struct desktop_stream *strm = (struct desktop_stream *)s;

    PJ_UNUSED_ARG(strm);

    PJ_ASSERT_RETURN(s && pval, PJ_EINVAL);

    if (cap == PJMEDIA_VID_DEV_CAP_INPUT_SCALE)
    {
        return PJMEDIA_EVID_INVCAP;
        //	return PJ_SUCCESS;
    }
    else
    {
        return PJMEDIA_EVID_INVCAP;
    }
}

/* API: set capability */
static pj_status_t desktop_stream_set_cap(pjmedia_vid_dev_stream *s,
                                          pjmedia_vid_dev_cap cap,
                                          const void *pval)
{
    struct desktop_stream *strm = (struct desktop_stream *)s;

    PJ_UNUSED_ARG(strm);

    PJ_ASSERT_RETURN(s && pval, PJ_EINVAL);

    if (cap == PJMEDIA_VID_DEV_CAP_INPUT_SCALE)
    {
        return PJ_SUCCESS;
    }

    return PJMEDIA_EVID_INVCAP;
}

/* API: Get frame from stream */
static pj_status_t desktop_stream_get_frame(pjmedia_vid_dev_stream *strm,
                                            pjmedia_frame *frame)
{
    struct desktop_stream *stream = (struct desktop_stream *)strm;

    frame->type = PJMEDIA_FRAME_TYPE_VIDEO;
    frame->bit_info = 0;
    frame->timestamp = stream->ts;
    stream->ts.u64 += stream->ts_inc;
    return capture(frame, stream);
}

/* API: Start stream. */
static pj_status_t desktop_stream_start(pjmedia_vid_dev_stream *strm)
{
    struct desktop_stream *stream = (struct desktop_stream *)strm;

    PJ_LOG(4, (THIS_FILE, "Starting desktop video stream"));

    if (stream->clock)
        return pjmedia_clock_start(stream->clock);

    return PJ_SUCCESS;
}

/* API: Stop stream. */
static pj_status_t desktop_stream_stop(pjmedia_vid_dev_stream *strm)
{
    struct desktop_stream *stream = (struct desktop_stream *)strm;

    PJ_LOG(4, (THIS_FILE, "Stopping desktop video stream"));

    if (stream->clock)
        return pjmedia_clock_stop(stream->clock);

    return PJ_SUCCESS;
}

/* API: Destroy stream. */
static pj_status_t desktop_stream_destroy(pjmedia_vid_dev_stream *strm)
{
    struct desktop_stream *stream = (struct desktop_stream *)strm;

    PJ_ASSERT_RETURN(stream != NULL, PJ_EINVAL);

    desktop_stream_stop(strm);

    if (stream->clock)
        pjmedia_clock_destroy(stream->clock);
    stream->clock = NULL;

    pj_pool_release(stream->pool);

    return PJ_SUCCESS;
}

#endif /* PJMEDIA_VIDEO_DEV_HAS_desktop_SRC */
