"""Gateway CGI methods.
"""
#
# Copyright (c) 2005-2015 shinGETsu Project.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

import re
import cgi
import csv
from operator import attrgetter
#from time import strftime, time
import time

from . import config
from . import mobile_gateway
from .cache import *
from .tag import UserTagList
from .rss import RSS, make_rss1
from .util import opentext

from http.cookies import SimpleCookie
import mimetypes
from . import attachutil

import random

class CGI(mobile_gateway.CGI):

    """Class for /m.cgi."""

    def run(self):
        path = self.path_info()
        self.form = cgi.FieldStorage(environ=self.environ, fp=self.stdin)
        try:
            filter = self.form.getfirst('filter', '')
            tag = self.form.getfirst('tag', '')
            if self.form.getfirst("cmd", "") == "post" and \
                self.form.getfirst("file", "").startswith("thread_") and \
                self.environ["REQUEST_METHOD"] == "POST":
                id = self.do_post(path, self.form)
                if not id:
                    return
                datfile = self.form.getfirst("file", "")
                title = self.str_encode(self.file_decode(datfile))
                self.print302(self.mobile_gateway_cgi + self.sep  + 'thread' + self.sep + title + "#r" + id)
                return
            elif filter:
                self.filter = filter.lower()
                self.str_filter = cgi.escape(filter, True)
            elif tag:
                self.tag = tag.lower()
                self.str_tag = cgi.escape(tag, True)
        except (re.error, UnicodeDecodeError):
            self.header(self.message['regexp_error'], deny_robot=True)
            self.footer()
            return

        if config.server_name:
            self.host = config.server_name
        else:
            self.host = self.environ.get('HTTP_HOST', 'localhost')

        if not self.check_visitor():
            self.print403()
            return
        elif path == "motd":
            self.print_motd()
        elif path == "new-posts":
            self.print_new_posts()
        elif path in ("recent", "new"):
            if (not self.isfriend) and (not self.isadmin):
                self.print403()
            elif path == "recent":
                self.print_recent()
            elif path == "new":
                self.header(self.message["new"], deny_robot=True)
                self.print_new_element_form()
                self.footer()
            else:
                self.print404()
        elif self.form.getfirst("cmd", "") == "new":
            self.jump_new_file()
        elif re.search(r"^thread/(thread_[0-9A-F]+)/([0-9a-f]{32})/s(\d+)\.(\d+x\d+)\.(.*)", path):
            found = re.search(r"^thread/(thread_[0-9A-F]+)/([0-9a-f]{32})/s(\d+)\.(\d+x\d+)\.(.*)", path)
            (datfile, stamp, id, thumbnail_size, suffix) = found.groups()
            self.print_attach(datfile, stamp, id, suffix, thumbnail_size)
            return
        elif re.search(r"^thread/(thread_[0-9A-F]+)/([0-9a-f]{32})/(\d+)\.(.*)", path):
            found = re.search(r"^thread/(thread_[0-9A-F]+)/([0-9a-f]{32})/(\d+)\.(.*)", path)
            (datfile, stamp, id, suffix) = found.groups()
            self.print_attach(datfile, stamp, id, suffix, None)
            return
        elif re.search(r"^(thread)", path) and not re.search(r"^thread(s|/.*)$", path):
            m = re.search(r"^(thread)/?([^/]*)$", path)
            if m is None:
                self.print_top_page()
                return
            elif m.group(2) != "":
                uri = self.appli[m.group(1)] + self.sep + \
                      self.str_encode(m.group(2))
            elif self.environ.get("QUERY_STRING", "") != "":
                uri = self.appli[m.group(1)] + self.sep + \
                      self.environ["QUERY_STRING"]
            else:
                self.print_top_page()
                return

            self.print302(uri)
        elif path == 'threads':
            self.print_threads()
        elif re.search(r"^thread/[^/]+$", path):
            m = re.search(r"^(thread)/([^/]+)$", path)
            self.print_thread(m.group(2))
        elif re.search(r"^(thread)/([^/]+)/p([0-9]+)$", path):
            m = re.search(r"^(thread)/([^/]+)/p([0-9]+)$", path)
            self.print_thread(m.group(2), page=int(m.group(3)))
        elif re.search(r"^(thread)/([^/]+)/([0-9a-f]{8})$", path):
            m = re.search(r"^(thread)/([^/]+)/([0-9a-f]{8})$", path)
            self.print_thread(m.group(2), id=m.group(3))
        elif path == '':
            self.print_top_page()
        else:
            self.print404()

    def print_top_page(self):
        message = self.message
        #cachelist = CacheList()
        #cachelist.sort(key=lambda x: x.valid_stamp, reverse=True)
        #now = int(time.time())
        #output_cachelist = []
        #for cache in cachelist:
        #    if now <= cache.valid_stamp + config.top_recent_range:
        #        output_cachelist.append(cache)
        #self.header(message['logo'] + ' - ' + message['description'])
        var = {
            'page_title': 'トップ - ' + self.message['logo'],
        #    'cachelist': output_cachelist,
            'target': 'changes',
            'taglist': UserTagList(),
            'mch_url': self.mch_url(),
            'mch_categories': self.mch_categories()
        }

        self.stdout.write(self.template('mobile_header', var))
        self.stdout.write(self.template('mobile_top', var))
        self.stdout.write(self.template('mobile_footer', var))
        #self.print_new_element_form()
        #self.footer()

    def print_thread(self, path, id='', page=0):
        str_path = self.str_encode(path)
        file_path = self.file_encode('thread', path)
        form = cgi.FieldStorage(environ=self.environ, fp=self.stdin)
        cache = Cache(file_path)
        if cache.has_record():
            pass
        elif self.check_get_cache():
            if not form.getfirst('search_new_file', ''):
                cache.standby_directories()
                self.unlock()
            else:
                self.get_cache(cache)
        else:
            self.print404(id=id)
            return

        ajax = form.getfirst('ajax')
        if id and ajax:
            self.stdout.write("Content-Type: text/html; charset=UTF-8\n\n");

            found = False
            for k in list(cache.keys()):
                rec = cache[k]
                if ((not id) or (rec.id[:8] == id)) and rec.load_body():
                    self.print_record(cache, rec, path, str_path, False, ajax)
                    found = True
            if found:
                self.stdout.write("<script>initializeAnchors();</script>")
            else:
                self.stdout.write("レスが見つかりません")
            return

        access = 0
        if config.use_cookie and len(cache) and (not id) and (not page):
            try:
                cookie = SimpleCookie(self.environ.get('HTTP_COOKIE', ''))
                if ('access_' + file_path) in cookie and 'access_new_posts' in cookie:
                    access = int(cookie['access_new_posts'].value)
                if ('access_' + file_path) in cookie and access < int(cookie['access_' + file_path].value):
                    access = int(cookie['access_' + file_path].value)
            except CookieError as err:
                self.stderr.write('%s\n' % err)
            newcookie = self.setcookie(cache, path)
        else:
            newcookie = ''
        #rss = self.gateway_cgi + '/rss'
        #self.header(path, rss=rss, cookie=newcookie)
        tags = form.getfirst('tag', '').strip().split()
        if self.isadmin and tags:
            cache.tags.add(tags)
            cache.tags.sync()
            user_tag_list = UserTagList()
            user_tag_list.add(tags)
            user_tag_list.sync()
        #self.print_tags(cache)
        lastrec = None
        ids = list(cache.keys())
        if len(cache) and (not page) and (not id) and (not ids):
            lastrec = cache[ids[-1]]
        page_size = config.thread_page_size
        num_pages = int((len(ids) + page_size - 1) / page_size)
        var = {
            'id': id,
            'cookie': newcookie,
            'page_title': path + ' - ' + self.message['logo'],
            'path': path,
            'str_path': str_path,
            'cache': cache,
            'lastrec': lastrec,
            'res_anchor': self.res_anchor,
            'page': page,
            'num_pages': num_pages,
        }
        #self.stdout.write(self.template('thread_top', var))
        self.stdout.write(self.template('mobile_header', var))
        self.stdout.write(self.template('mobile_thread_header', var))
        #self.print_page_navi(page, cache, path, str_path, id)
        #self.stdout.write('</p>\n<dl id="records">\n')
        if id:
            inrange = ids
        elif page:
            inrange = ids[-page_size*(page+1):-page_size*page]
        else:
            inrange = ids[-page_size*(page+1):]
        printed = False
        for k in inrange:
            rec = cache[k]
            if ((not id) or (rec.id[:8] == id)) and rec.load_body():
                new_record = True
                if (access and access >= rec.stamp) or id or page != 0:
                    new_record = False
                self.print_record(cache, rec, path, str_path, new_record, False)
                printed = True
            rec.free()
        #self.stdout.write("</dl>\n")
        escaped_path = cgi.escape(path)
        escaped_path = re.sub(r'  ', '&nbsp;&nbsp;', escaped_path)
        suffixes = list(mimetypes.types_map.keys())
        suffixes.sort()
        related_threads = None;
        if False and len(cache.tags) > 0 and not id:
            related_threads = CacheList()
            try:
                related_threads = [x for x in related_threads if ((str(x) != str(cache)) and len(set([str(t).lower() for t in cache.tags]) & set([str(t).lower() for t in x.tags])) > 0  )]
            except ValueError:
                pass
            related_threads = random.sample(related_threads, min(5, len(related_threads)))
        var = {
            'path': path,
            'id': id,
            'str_path': str_path,
            'cache': cache,
            'lastrec': lastrec,
            'res_anchor': self.res_anchor,
            'page': page,
            'num_pages': num_pages,
            'suffixes': suffixes,
            'limit': config.record_limit * 3 // 4,
            'related_threads': related_threads,
            'post_message': self.form.getfirst('message', ''),
        }
        #self.stdout.write(self.template('thread_bottom', var))
        self.stdout.write(self.template('mobile_thread_footer', var))
        self.stdout.write(self.template('mobile_footer', var))
        #if len(cache):
        #    self.print_page_navi(page, cache, path, str_path, id)
        #    self.stdout.write('</p>\n')
        #self.print_post_form(cache)
        #self.print_tags(cache)
        #self.remove_file_form(cache, escaped_path)
        #self.footer(menubar=self.menubar('bottom', rss))

    def setcookie(self, cache, title):
        file_path = self.file_encode('thread', title)

        now = int(time.time())
        expires = time.strftime('%a, %d %b %Y %H:%M:%S GMT',
                                time.gmtime(now + config.save_cookie))
        cookie = SimpleCookie()
        cookie['access_' + file_path] = str(now)
        cookie['access_' + file_path]['path'] = '/'
        cookie['access_' + file_path]['expires'] = expires

        return cookie

    def setcookie_for_new_posts(self):
        now = int(time.time())
        expires = time.strftime('%a, %d %b %Y %H:%M:%S GMT',
                                time.gmtime(now + config.save_cookie))
        cookie = SimpleCookie()
        cookie['access_new_posts'] = str(now)
        cookie['access_new_posts']['path'] = '/'
        cookie['access_new_posts']['expires'] = expires
        return cookie

    def print_record(self, cache, rec, path, str_path, new_record, ajax):
        thumbnail_size = None
        if 'attach' in rec:
            attach_file = rec.attach_path()
            attach_size = rec.attach_size(attach_file)
            suffix = rec.get('suffix', '')
            if not re.search('^[0-9A-Za-z]+$', suffix):
                suffix = 'txt'
            (type, null) = mimetypes.guess_type("test." + suffix)
            if type is None:
                type = "text/plain"
            if attachutil.is_valid_image(type, attach_file):
                thumbnail_size = config.thumbnail_size
        else:
            attach_file = None
            attach_size = None
            suffix = None
        if 'body' in rec:
            body = rec['body']
        else:
            body = ''
        body = self.html_format(body, self.mobile_gateway_cgi + self.sep + 'thread', path)
        var = {
            'ajax': ajax,
            'cache': cache,
            'rec': rec,
            'sid': rec['id'][:8],
            'path': path,
            'str_path': str_path,
            'attach_file': attach_file,
            'attach_size': attach_size,
            'suffix': suffix,
            'body': body,
            'res_anchor': self.res_anchor,
            'thumbnail': thumbnail_size,
            'new_record': new_record,
        }
        self.stdout.write(self.template('mobile_record', var))

    def print_attach(self, datfile, id, stamp, suffix, thumbnail_size=None):
        """Print attachment."""
        cache = Cache(datfile)
        (type, null) = mimetypes.guess_type("test." + suffix)
        if type is None:
            type = "text/plain"
        if cache.has_record():
            pass
        elif self.check_get_cache():
            self.get_cache(cache)
        else:
            self.print404(cache)
            return
        rec = Record(datfile=cache.datfile, idstr=stamp+'_'+id)
        if not rec.exists():
            self.print404(cache)
            return
        attach_file = rec.attach_path(suffix=suffix, thumbnail_size=thumbnail_size)
        if config.thumbnail_size is not None and not os.path.isfile(attach_file):
            if config.force_thumbnail or thumbnail_size == config.thumbnail_size:
                rec.make_thumbnail(suffix=suffix, thumbnail_size=thumbnail_size)
        if attach_file is not None:
            size = rec.attach_size(suffix=suffix, thumbnail_size=thumbnail_size)
            self.stdout.write(
                "Content-Type: " + type + "\n" +
                "Last-Modified: " + self.rfc822_time(stamp) + "\n" +
                "Content-Length: " + str(size) + "\n")
            if not attachutil.is_valid_image(type, attach_file):
                self.stdout.write("Content-Disposition: attachment\n")
            self.stdout.write("\n")
            try:
                f = open(attach_file, "rb")
                buf = f.read(1024)
                while (buf != b''):
                    self.stdout.write(buf)
                    buf = f.read(1024)
                f.close()
            except IOError:
                self.print404(cache)

    def print_threads(self):
        cookie = None
        if config.use_cookie:
            cookie = SimpleCookie(self.environ.get('HTTP_COOKIE', ''))

        if self.str_filter:
            title = '%s : %s' % (self.message['changes'], self.str_filter)
        else:
            title = self.message['changes']
        cachelist = CacheList()
        cachelist.sort(key=lambda x: x.valid_stamp, reverse=True)
        var = {
            'page_title': 'スレッド一覧',
            'target': 'changes',
            'type': 'thread',
            'filter': self.str_filter,
            'tag': self.str_tag,
            'taglist': UserTagList(),
            'cachelist': cachelist,
            'search_new_file': False,
            'cookie': cookie,
        }
        self.stdout.write(self.template('mobile_header', var))
        self.stdout.write(self.template('mobile_threads_header', var))
        for cache in cachelist:
            if cache.type == 'thread':
                self.stdout.write(self.make_list_item(cache, target='changes', search=False, cookie=cookie))
        self.stdout.write(self.template('mobile_threads_footer', var))
        self.stdout.write(self.template('mobile_footer', var))
            
    def print_index(self):
        """Print index page."""
        if self.str_filter:
            title = '%s : %s' % (self.message['index'], self.str_filter)
        else:
            title = self.message['index']
        self.header(title)
        self.print_paragraph(self.message['desc_index'])
        cachelist = CacheList()
        cachelist.sort(key=attrgetter('velocity', 'count'), reverse=True)
        self.print_index_list(cachelist, "index")

    def rss_text_format(self, plain):
        buf = plain.replace("<br>", " ")
        buf = buf.replace("&", "&amp;")
        buf = re.sub(r'&amp;(#\d+|lt|gt|amp);', r'&\1;', buf)
        buf = buf.replace("<", "&lt;")
        buf = buf.replace(">", "&gt;")
        buf = buf.replace("\r", "")
        buf = buf.replace("\n", "")
        return buf

    def rss_html_format(self, plain, appli, path):
        title = self.str_decode(path)
        buf = self.html_format(plain, appli, title, absuri=True)
        if buf:
            buf = '<p>%s</p>' % buf
        return buf

    def print_new_posts(self):
        access = 0
        if config.use_cookie:
            try:
                cookie = SimpleCookie(self.environ.get('HTTP_COOKIE', ''))
                if 'access_new_posts' in cookie:
                    access = int(cookie['access_new_posts'].value)
            except CookieError as err:
                self.stderr.write('%s\n' % err)
            newcookie = self.setcookie_for_new_posts()
        else:
            newcookie = ''

        var = {
            'page_title': '新着レスまとめ読み',
            'cookie': newcookie,
        }
        self.stdout.write(self.template('mobile_header', var))
        self.stdout.write('<h3>' + var['page_title'] + '</h3>');

        cachelist = CacheList()
        now = int(time.time())
        new_posts_count = 0
        for cache in cachelist:
            title = self.escape(self.file_decode(cache.datfile))
            file_path = self.file_encode('thread', title)
            access_thread = 0
            if config.use_cookie and 'access_' + file_path in cookie:
                access_thread = int(cookie['access_' + file_path].value)

            if access_thread > 0 and cache.valid_stamp + config.rss_range >= now and access < cache.valid_stamp and access_thread < cache.valid_stamp:
                str_path = self.str_encode(title)
                self.stdout.write('<div class="panel panel-info">');
                self.stdout.write('<div class="panel-heading" style="color:black;"><h4 style="margin:0">');
                self.stdout.write('<a style="color:black" target="_blank" href="' + self.mobile_gateway_cgi + '/thread/' + str_path + '">');
                self.stdout.write(title);
                self.stdout.write('</a></h4></div><div class="panel-body" style="margin:0;padding:10px 10px 0px 10px;">');
                for r in cache:
                    if r.stamp + config.rss_range < now or access >= r.stamp or access_thread >= r.stamp:
                        continue
                    r.load_body()
                    desc = self.rss_text_format(r.get("body", ""))
                    content = self.rss_html_format(r.get("body", ""),
                                                   self.appli[cache.type],
                                                   title)
                    self.print_record(cache, r, title, str_path, False, False)
                    new_posts_count = new_posts_count + 1
                    r.free()
                self.stdout.write("</div></div>");
        if new_posts_count == 0:
            self.stdout.write("<p>このページには既読スレッドの新着レスが表示されます。</p>");
            self.stdout.write("<p>新着レスはありません。</p>");
        self.stdout.write(self.template('mobile_new_posts_footer', var))
        self.stdout.write(self.template('mobile_footer', var))

    def make_recent_cachelist(self):
        """Make dummy cachelist from recentlist."""
        recentlist = RecentList()[:]
        recentlist.sort(key=lambda x: x.stamp, reverse=True)
        cachelist = []
        check = []
        for rec in recentlist:
            if rec.datfile not in check:
                cache = Cache(rec.datfile)
                cache.recent_stamp = rec.stamp
                cachelist.append(cache)
                check.append(rec.datfile)
        return cachelist

    def print_recent(self):
        """Print changes page."""
        if self.str_filter:
            title = '%s : %s' % (self.message['recent'], self.str_filter)
        else:
            title = self.message['recent']
        self.header(title)
        self.print_paragraph(self.message['desc_recent'])
        cachelist = self.make_recent_cachelist()
        self.print_index_list(cachelist, "recent", search_new_file=True)

    def jump_new_file(self):
        if self.form.getfirst("link", "") == "":
            self.header(self.message["null_title"], deny_robot=True)
            self.footer()
        elif re.search(r"[/\[\]<>]", self.form.getfirst("link", "")):
            self.header(self.message["bad_title"], deny_robot=True)
            self.footer()
        elif self.form.getfirst("type", "") == "":
            self.header(self.message["null_type"], deny_robot=True)
            self.footer()
        elif self.form.getfirst("type", "") in config.types:
            tag = self.str_encode(self.form.getfirst('tag', ''))
            search = self.str_encode(self.form.getfirst('search_new_file', ''))
            self.print302(self.appli[self.form.getfirst("type", "")] +
                          self.sep +
                          self.str_encode(self.form.getfirst("link", "")) +
                          '?tag=' + tag +
                          '&search_new_file=' + search)
        else:
            self.print404()

    def print_motd(self):
        self.stdout.write("Content-Type: text/plain; charset=UTF-8\n\n")
        try:
            self.stdout.write(opentext(config.motd).read())
        except IOError:
            self.stderr.write(config.motd + ": IOError\n")

# End of CGI
