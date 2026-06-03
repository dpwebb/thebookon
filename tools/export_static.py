from __future__ import annotations

import html
import json
import re
import shutil
import sys
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse, urlsplit, urlunsplit
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
ASSETS = PUBLIC / "assets"
SOURCE = "https://thebookon.ca"
API = f"{SOURCE}/wp-json/wp/v2"


@dataclass(frozen=True)
class PageSpec:
    slug: str
    path: str
    nav: str
    title: str | None = None
    fallback: str | None = None


PAGES = [
    PageSpec("home", "index.html", "Home", "Empower Your Words with The Book On Publishing"),
    PageSpec("series", "series/index.html", "Series"),
    PageSpec("authors", "authors/index.html", "Authors"),
    PageSpec("author-success-guides", "author-success-guides/index.html", "Writing"),
    PageSpec("the-book-on-getting-published", "the-book-on-getting-published/index.html", "Publishing"),
    PageSpec("the-book-on-book-marketing", "the-book-on-book-marketing/index.html", "Marketing"),
    PageSpec("author-book-template", "author-book-template/index.html", "Books", "Published Authors & Books"),
    PageSpec(
        "manuscript-submission",
        "manuscript-submission/index.html",
        "Submit",
        "Manuscript Submission",
        "<p>The manuscript submission portal is being connected to the new Git-backed site. Please use the contact page while account tools are being restored.</p>",
    ),
    PageSpec(
        "login",
        "login/index.html",
        "Login",
        "Login",
        "<p>Author account tools are being connected to the new Git-backed site. Please check back soon or use the contact page.</p>",
    ),
    PageSpec(
        "register",
        "register/index.html",
        "Register",
        "Register",
        "<p>New author registration is being connected to the new Git-backed site. Please use the contact page to start a publishing conversation.</p>",
    ),
    PageSpec("contact-us", "contact-us/index.html", "Contact", "Contact Us"),
    PageSpec("7134-2", "7134-2/index.html", "Self Publishing", "Self Publishing Through Our Team"),
    PageSpec(
        "my-author-account",
        "my-author-account/index.html",
        "Author Dashboard",
        "Author Dashboard",
        "<p>The author dashboard is being connected to the new Git-backed site. Please use the contact page for account or submission questions.</p>",
    ),
    PageSpec(
        "password-reset",
        "password-reset/index.html",
        "Password Reset",
        "Password Reset",
        "<p>Password reset is being connected to the new Git-backed site. Please use the contact page if you need author account support.</p>",
    ),
    PageSpec("terms-conditions", "terms-conditions/index.html", "Terms"),
    PageSpec("privacy-policy", "privacy-policy/index.html", "Privacy"),
]

NAV = [
    ("Home", "/"),
    ("Series", "/series/"),
    ("Authors", "/authors/"),
    ("Publishing", "/the-book-on-getting-published/"),
    ("Writing", "/author-success-guides/"),
    ("Submit", "/manuscript-submission/"),
    ("Contact", "/contact-us/"),
]


class Sanitizer(HTMLParser):
    allowed = {
        "article",
        "blockquote",
        "br",
        "div",
        "em",
        "figcaption",
        "figure",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "li",
        "ol",
        "p",
        "section",
        "span",
        "strong",
        "ul",
    }
    skip = {"script", "style", "noscript", "svg", "iframe", "form", "input", "button", "textarea", "select"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.skip:
            self.skip_depth += 1
            return
        if self.skip_depth:
            return
        if tag == "a":
            href = dict(attrs).get("href", "#") or "#"
            href = clean_link(href)
            self.out.append(f'<a href="{html.escape(href, quote=True)}">')
            return
        if tag in self.allowed:
            self.out.append(f"<{tag}>")

    def handle_endtag(self, tag: str) -> None:
        if tag in self.skip and self.skip_depth:
            self.skip_depth -= 1
            return
        if self.skip_depth:
            return
        if tag == "a":
            self.out.append("</a>")
        elif tag in self.allowed and tag != "br":
            self.out.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if not self.skip_depth:
            self.out.append(html.escape(data))

    def get_html(self) -> str:
        text = "".join(self.out)
        text = re.sub(r"<p>\s*</p>", "", text)
        text = re.sub(r"<(div|section|span)>\s*</\1>", "", text)
        text = re.sub(r"\s+", " ", text)
        text = re.sub(r">\s+<", "><", text)
        text = text.replace("Read more", "")
        return text.strip()


def fetch_json(url: str):
    request = Request(url, headers={"User-Agent": "thebookon-static-export/1.0"})
    with urlopen(request, timeout=25) as response:
        return json.loads(response.read().decode("utf-8"))


def download(url: str, target: Path) -> bool:
    request = Request(safe_url(url), headers={"User-Agent": "thebookon-static-export/1.0"})
    try:
        with urlopen(request, timeout=30) as response:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as handle:
                shutil.copyfileobj(response, handle)
        return True
    except (HTTPError, URLError, TimeoutError) as exc:
        print(f"Could not download {url}: {exc}", file=sys.stderr)
        return False


def safe_url(url: str) -> str:
    parts = urlsplit(url)
    path = quote(parts.path, safe="/:%")
    query = quote(parts.query, safe="=&?/:.%")
    return urlunsplit((parts.scheme, parts.netloc, path, query, parts.fragment))


def clean_link(href: str) -> str:
    if href.startswith(SOURCE):
        parsed = urlparse(href)
        return parsed.path or "/"
    return href


def text_from_rendered(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html.unescape(value))).strip()


def sanitize_content(rendered: str) -> str:
    parser = Sanitizer()
    parser.feed(rendered)
    return parser.get_html()


def page_url(path: str) -> str:
    if path == "index.html":
        return "/"
    return "/" + path.replace("index.html", "")


def active_nav(current_path: str) -> str:
    current_url = page_url(current_path)
    links = []
    for label, href in NAV:
        current = ' aria-current="page"' if href == current_url else ""
        links.append(f'<a href="{href}"{current}>{html.escape(label)}</a>')
    return "\n".join(links)


def shell(content: str, title: str, path: str, description: str, extra: str = "") -> str:
    nav = active_nav(path)
    canonical = f"https://thebookon.ca{page_url(path)}"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <meta name="description" content="{html.escape(description, quote=True)}">
  <link rel="canonical" href="{canonical}">
  <meta property="og:title" content="{html.escape(title, quote=True)}">
  <meta property="og:description" content="{html.escape(description, quote=True)}">
  <meta property="og:image" content="https://thebookon.ca/assets/default-social-image-1200x630-px.png">
  <meta property="og:type" content="website">
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <header class="site-header">
    <div class="header-inner">
      <a class="brand" href="/">
        <img src="/assets/thebookonlogo-transparent.png" alt="" width="54" height="54">
        <span>The Book On Publishing</span>
      </a>
      <nav class="nav" aria-label="Main navigation">
        {nav}
      </nav>
    </div>
  </header>
  {content}
  {extra}
  <footer class="site-footer">
    <div class="footer-inner">
      <span>&copy; The Book On Publishing</span>
      <span><a href="/privacy-policy/">Privacy Policy</a> · <a href="/terms-conditions/">Terms & Conditions</a></span>
    </div>
  </footer>
</body>
</html>
"""


def home_page(page: dict, covers: list[tuple[str, str]]) -> str:
    description = "Join The Book On Publishing to self-publish nonfiction skills books. Keep ownership, get professional editing, and reach readers worldwide."
    content = sanitize_content(page["content"]["rendered"])
    cover_html = "\n".join(
        f'<div class="cover"><img src="/assets/covers/{html.escape(file)}" alt="{html.escape(alt)}"></div>'
        for file, alt in covers[:12]
    )
    body = f"""
  <section class="hero">
    <div class="section-inner hero-content">
      <p class="eyebrow">Nonfiction publishing for independent thinkers</p>
      <h1>The Book On Publishing</h1>
      <p class="lead">Self-publishing support, selective series publishing, editing, design, and distribution for authors who teach real-world skills.</p>
      <div class="actions">
        <a class="button" href="/manuscript-submission/">Submit Manuscript</a>
        <a class="button secondary" href="/series/">Explore The Series</a>
      </div>
    </div>
  </section>
  <section class="section">
    <div class="section-inner content">
      {content}
    </div>
  </section>
  <section class="section alt">
    <div class="section-inner">
      <p class="eyebrow">Selected titles</p>
      <h2>The Book On Series</h2>
      <div class="covers">{cover_html}</div>
    </div>
  </section>
"""
    return shell(body, "Empower Your Words with The Book On Publishing", "index.html", description)


def standard_page(spec: PageSpec, page: dict | None, covers: list[tuple[str, str]]) -> str:
    title = spec.title or (text_from_rendered(page["title"]["rendered"]) if page else spec.nav)
    rendered = page["content"]["rendered"] if page else ""
    main = sanitize_content(rendered)
    if spec.fallback:
        main = spec.fallback
    if not main:
        main = "<p>This page is being refreshed as part of the Git-backed Hostinger migration.</p>"
    description = text_from_rendered(page.get("excerpt", {}).get("rendered", "")) if page else title
    if not description:
        description = "The Book On Publishing public page."
    cover_section = ""
    if spec.slug == "series" and covers:
        cover_html = "\n".join(
            f'<div class="cover"><img src="/assets/covers/{html.escape(file)}" alt="{html.escape(alt)}"></div>'
            for file, alt in covers
        )
        cover_section = f'<h2>Series Covers</h2><div class="covers">{cover_html}</div>'
    body = f"""
  <main class="section">
    <div class="section-inner content">
      <p class="eyebrow">The Book On Publishing</p>
      <h1>{html.escape(title)}</h1>
      {main}
      {cover_section}
    </div>
  </main>
"""
    return shell(body, title, spec.path, description)


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def output_path_from_link(link: str) -> str:
    parsed = urlparse(link)
    path = parsed.path.strip("/")
    if not path:
        return "index.html"
    return f"{path}/index.html"


def media_filename(url: str, fallback: str) -> str:
    match = re.search(r"/wp-content/uploads/\d+/\d+/([^/?]+)", url)
    name = match.group(1) if match else Path(urlparse(url).path).name
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", name) or fallback
    return name.replace("×", "x")


def export_assets() -> list[tuple[str, str]]:
    ASSETS.mkdir(parents=True, exist_ok=True)
    logo_items = fetch_json(f"{API}/media?search=TheBookOnLogo&per_page=3&_fields=source_url,alt_text,title")
    social_items = fetch_json(f"{API}/media?search=default-social-image&per_page=1&_fields=source_url,alt_text,title")
    if logo_items:
        download(logo_items[-1]["source_url"], ASSETS / "thebookonlogo-transparent.png")
    if social_items:
        download(social_items[0]["source_url"], ASSETS / "default-social-image-1200x630-px.png")

    covers: list[tuple[str, str]] = []
    media = fetch_json(f"{API}/media?per_page=100&_fields=source_url,alt_text,title")
    cover_dir = ASSETS / "covers"
    if cover_dir.exists():
        shutil.rmtree(cover_dir)
    cover_dir.mkdir(parents=True, exist_ok=True)
    seen_volumes: set[int] = set()
    for item in media:
        title = text_from_rendered(item["title"]["rendered"]).lower()
        volume = re.match(r"^(\d+)\s", title)
        if not volume:
            continue
        volume_number = int(volume.group(1))
        if volume_number < 1 or volume_number > 29 or volume_number in seen_volumes:
            continue
        source_url = item["source_url"]
        file_name = media_filename(source_url, f"{title}.png")
        if download(source_url, cover_dir / file_name):
            alt = item.get("alt_text") or text_from_rendered(item["title"]["rendered"])
            covers.append((file_name, alt))
            seen_volumes.add(volume_number)
    covers.sort(key=lambda pair: int(re.match(r"^(\d+)", pair[0]).group(1)) if re.match(r"^(\d+)", pair[0]) else 999)
    return covers


def export_public_files(rendered_items: Iterable[str]) -> None:
    seen: set[str] = set()
    for rendered in rendered_items:
        for match in re.finditer(r"""href=["'](?:https://thebookon\.ca)?(/wp-content/uploads/[^"']+\.(?:pdf|docx?|xlsx?))["']""", rendered):
            path = html.unescape(match.group(1))
            if path in seen:
                continue
            seen.add(path)
            download(f"{SOURCE}{path}", PUBLIC / path.lstrip("/"))


def export_collection(endpoint: str, fallback_prefix: str) -> list[dict]:
    try:
        return fetch_json(f"{API}/{endpoint}?per_page=100&_fields=slug,link,title,excerpt,content")
    except Exception as exc:
        print(f"Could not export {endpoint}: {exc}", file=sys.stderr)
        return []


def collection_page(item: dict) -> str:
    path = output_path_from_link(item["link"])
    title = text_from_rendered(item["title"]["rendered"])
    description = text_from_rendered(item.get("excerpt", {}).get("rendered", "")) or title
    body = f"""
  <main class="section">
    <div class="section-inner content">
      <p class="eyebrow">The Book On Publishing</p>
      <h1>{html.escape(title)}</h1>
      {sanitize_content(item["content"]["rendered"])}
    </div>
  </main>
"""
    return shell(body, title, path, description)


def alias_page(path: str, title: str, destination: str, message: str) -> None:
    body = f"""
  <main class="section">
    <div class="section-inner content">
      <p class="eyebrow">The Book On Publishing</p>
      <h1>{html.escape(title)}</h1>
      <p>{html.escape(message)}</p>
      <p><a class="button" href="{html.escape(destination)}">Continue</a></p>
    </div>
  </main>
"""
    write(PUBLIC / path, shell(body, title, path, message))


def main() -> None:
    pages = fetch_json(f"{API}/pages?per_page=100&_fields=slug,title,excerpt,content,link")
    by_slug = {page["slug"]: page for page in pages}
    covers = export_assets()
    books = export_collection("book", "books")
    authors = export_collection("author_profile", "authors")
    export_public_files([page["content"]["rendered"] for page in pages] + [item["content"]["rendered"] for item in books + authors])
    for spec in PAGES:
        page = by_slug.get(spec.slug)
        output = home_page(page, covers) if spec.slug == "home" and page else standard_page(spec, page, covers)
        write(PUBLIC / spec.path, output)
    for item in books + authors:
        write(PUBLIC / output_path_from_link(item["link"]), collection_page(item))
    alias_page(
        "elementor-page-6799/index.html",
        "Submit Your Manuscript",
        "/manuscript-submission/",
        "This legacy submission link now points to the manuscript submission page.",
    )
    write(
        PUBLIC / "404.html",
        shell(
            '<main class="section"><div class="section-inner content"><p class="eyebrow">Not found</p><h1>Page not found</h1><p>The page you requested is not available on the current site.</p><p><a class="button" href="/">Return home</a></p></div></main>',
            "Page Not Found",
            "404.html",
            "The requested The Book On Publishing page was not found.",
        ),
    )


if __name__ == "__main__":
    main()
