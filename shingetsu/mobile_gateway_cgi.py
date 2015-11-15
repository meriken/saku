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
        elif path == "mergedjs":
            self.print_mergedjs()
        elif path == "rss":
            self.print_rss()
        elif path == 'recent_rss':
            self.print_recent_rss()
        elif path == "index":
            self.print_index()
        elif path == "changes":
            self.print_changes()
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
        elif path.startswith("csv"):
            self.print_csv(path)
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
        cachelist = CacheList()
        cachelist.sort(key=lambda x: x.valid_stamp, reverse=True)
        now = int(time.time())
        output_cachelist = []
        for cache in cachelist:
            if now <= cache.valid_stamp + config.top_recent_range:
                output_cachelist.append(cache)
        #self.header(message['logo'] + ' - ' + message['description'])
        var = {
            'page_title': 'トップ - ' + self.message['logo'],
            'cachelist': output_cachelist,
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
            for k in list(cache.keys()):
                rec = cache[k]
                if ((not id) or (rec.id[:8] == id)) and rec.load_body():
                    self.print_record(cache, rec, path, str_path, False, ajax)
            self.stdout.write("<script>initializeAnchors();</script>")
            return

        access = None
        if config.use_cookie and len(cache) and (not id) and (not page):
            try:
                cookie = SimpleCookie(self.environ.get('HTTP_COOKIE', ''))
                if 'access' in cookie:
                    access = cookie['access'].value
            except CookieError as err:
                self.stderr.write('%s\n' % err)
            newcookie = self.setcookie(cache, access)
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
                if (access and int(access) >= rec.stamp) or id or page != 0:
                    new_record = False
                self.print_record(cache, rec, path, str_path, new_record, False)
                printed = True
            rec.free()
        #self.stdout.write("</dl>\n")
        escaped_path = cgi.escape(path)
        escaped_path = re.sub(r'  ', '&nbsp;&nbsp;', escaped_path)
        suffixes = list(mimetypes.types_map.keys())
        suffixes.sort()
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

    def setcookie(self, cache, access):
        now = int(time.time())
        expires = time.strftime('%a, %d %b %Y %H:%M:%S GMT',
                                time.gmtime(now + config.save_cookie))
        path = self.mobile_gateway_cgi + '/thread/' + \
                  self.str_encode(self.file_decode(cache.datfile))
        cookie = SimpleCookie()
        cookie['access'] = str(now)
        cookie['access']['path'] = path
        cookie['access']['expires'] = expires
        if access:
            cookie['tmpaccess'] = str(access)
            cookie['tmpaccess']['path'] = '/'
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
        }
        self.stdout.write(self.template('mobile_header', var))
        self.stdout.write(self.template('mobile_threads', var))
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

    def print_changes(self):
        """Print changes page."""
        if self.str_filter:
            title = '%s : %s' % (self.message['changes'], self.str_filter)
        else:
            title = self.message['changes']
        self.header(title)
        self.print_paragraph(self.message['desc_changes'])
        cachelist = CacheList()
        cachelist.sort(key=lambda x: x.valid_stamp, reverse=True)
        self.print_index_list(cachelist, "changes")

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

    def print_csv(self, path):
        """CSV output as API."""
        found = re.search(r"^csv/([^/]+)/(.+)", path)
        if found:
            target, cols = found.groups()
        else:
            self.print404()
            return
        cols = cols.split(",")
        if target == "index":
            cachelist = CacheList()
        elif target == "changes":
            cachelist = CacheList()
            cachelist.sort(key=lambda x: x.valid_stamp, reverse=True)
        elif target == "recent":
            if (not self.isfriend) and (not self.isadmin):
                self.print403()
                return
            cachelist = self.make_recent_cachelist()
        else:
            self.print404()
            return
        self.stdout.write("Content-Type: text/comma-separated-values;" +
                          " charset=UTF-8\n\n")
        writer = csv.writer(self.stdout)
        for cache in cachelist:
            title = self.file_decode(cache.datfile)
            if cache.type in config.types:
                type = cache.type
                path = self.appli[cache.type] + self.sep + \
                       self.str_encode(title)
            else:
                type = ""
                path = ""
            row = []
            for c in cols:
                if c == "file":
                    row.append(cache.datfile)
                elif c == "stamp":
                    row.append(cache.valid_stamp)
                elif c == "date":
                    row.append(self.localtime(cache.valid_stamp))
                elif c == "path":
                    row.append(path)
                elif c == "uri":
                    if self.host and path:
                        row.append("http://" + self.host + path)
                    else:
                        row.append("")
                elif c == "type":
                    row.append(cache.type)
                elif c == "title":
                    row.append(title)
                elif c == "records":
                    row.append(len(cache))
                elif c == "size":
                    row.append(cache.size)
                elif c == 'tag':
                    row.append(str(cache.tags))
                elif c == 'sugtag':
                    row.append(str(cache.sugtags))
                else:
                    row.append("")
            writer.writerow(row)

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

    def print_rss(self):
        rss = RSS(encode = "UTF-8",
                  title = self.message["logo"],
                  parent = "http://" + self.host,
                  uri = "http://" + self.host
                                  + self.gateway_cgi + self.sep + "rss",
                  description = self.message["description"],
                  xsl = config.xsl)
        cachelist = CacheList()
        now = int(time.time())
        for cache in cachelist:
            if cache.valid_stamp + config.rss_range >= now:
                title = self.escape(self.file_decode(cache.datfile))
                path = self.appli[cache.type]+self.sep+self.str_encode(title)
                for r in cache:
                    if r.stamp + config.rss_range < now:
                        continue
                    r.load_body()
                    desc = self.rss_text_format(r.get("body", ""))
                    content = self.rss_html_format(r.get("body", ""),
                                                   self.appli[cache.type],
                                                   title)
                    attach = r.get('attach', '')
                    if attach:
                        suffix = r.get('suffix', '')
                        if not re.search(r'^[0-9A-Za-z]+$', suffix):
                            suffix = txt
                        content += '\n    <p>' + \
                            '<a href="http://%s%s%s%s/%s/%d.%s">%d.%s</a></p>'\
                            % (self.host, self.appli[cache.type], self.sep,
                               cache.datfile,
                               r.id, r.stamp, suffix,
                               r.stamp, suffix)
                    if cache.type == "thread":
                        permapath = "%s/%s" % (path[1:], r.id[:8])
                    else:
                        permapath = path[1:]
                    rss.append(
                        permapath,
                        date = r.stamp,
                        title = title,
                        creator = self.rss_text_format(r.get('name', '')),
                        subject = [str(i) for i in cache.tags],
                        description = desc,
                        content = content)
                    r.free()

        self.stdout.write("Content-Type: text/xml; charset=UTF-8\n")
        try:
            self.stdout.write("Last-Modified: %s\n" %
                              self.rfc822_time(rss[list(rss.keys())[0]].date))
        except IndexError as KeyError:
            pass
        self.stdout.write("\n")
        self.stdout.write(make_rss1(rss))

    def print_recent_rss(self):
        rss = RSS(encode = 'UTF-8',
                  title = '%s - %s' % (
                          self.message['recent'], self.message['logo']),
                  parent = 'http://' + self.host,
                  uri = 'http://' + self.host
                                  + self.gateway_cgi + self.sep + 'recent_rss',
                  description = self.message['desc_recent'],
                  xsl = config.xsl)
        cachelist = self.make_recent_cachelist()
        for cache in cachelist:
            title = self.escape(self.file_decode(cache.datfile))
            tags = list(set([str(t) for t in cache.tags + cache.sugtags]))
            if cache.type not in self.appli:
                continue
            rss.append(
                self.appli[cache.type][1:]+self.sep+self.str_encode(title),
                date = cache.recent_stamp,
                title = title,
                subject = tags,
                content = cgi.escape(title))

        self.stdout.write('Content-Type: text/xml; charset=UTF-8\n')
        try:
            self.stdout.write('Last-Modified: %s\n' %
                              self.rfc822_time(rss[list(rss.keys())[0]].date))
        except IndexError as KeyError:
            pass
        self.stdout.write('\n')
        self.stdout.write(make_rss1(rss))

    def print_mergedjs(self):
        self.stdout.write('Content-Type: application/javascript;'
            + ' charset=UTF-8')
        self.stdout.write('Last-Modified: '
            + self.rfc822_time(self.jscache.mtime) + '\n')
        self.stdout.write('\n')
        self.stdout.write(self.jscache.script)

    def print_motd(self):
        self.stdout.write("Content-Type: text/plain; charset=UTF-8\n\n")
        try:
            self.stdout.write(opentext(config.motd).read())
        except IOError:
            self.stderr.write(config.motd + ": IOError\n")

# End of CGI
