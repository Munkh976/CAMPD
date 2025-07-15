import json
import bcrypt
import logging
from pathlib import Path
from datetime import datetime
from datasette import hookimpl
from datasette.utils.asgi import Response
from email.parser import BytesParser
from email.policy import default
import bleach
import re

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'.jpg', '.png'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def sanitize_text(text):
    """Sanitize text by stripping HTML tags while preserving safe characters."""
    return bleach.clean(text, tags=[], strip=True)

def parse_markdown_links(text):
    """Parse markdown-like links [text](url) into HTML <a> tags and split into paragraphs."""
    paragraphs = [p.strip() for p in text.split('\n') if p.strip()]
    parsed_paragraphs = []
    link_pattern = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
    for paragraph in paragraphs:
        # Replace [text](url) with <a href="url">text</a>
        parsed = link_pattern.sub(lambda m: f'<a href="{sanitize_text(m.group(2))}" class="text-accent hover:text-primary">{sanitize_text(m.group(1))}</a>', paragraph)
        parsed_paragraphs.append(parsed)
    return parsed_paragraphs

async def login_page(datasette, request):
    logger.debug(f"Login request: method={request.method}, scope={request.scope}")
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Login Cookies: {cookies}")

    if request.method == "POST":
        post_vars = await request.post_vars()
        logger.debug(f"POST vars: {post_vars}")
        username = post_vars.get("username")
        password = post_vars.get("password")
        try:
            db = datasette.get_database("CAMPD")
            result = await db.execute("SELECT password_hash FROM users WHERE username = ?", [username])
            user = result.first()
            if user and bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')):
                logger.debug("Login successful for user: %s", username)
                response = Response.redirect("/admin")
                actor_data = {"id": username, "name": f"User {username}"}
                response.set_cookie("ds_actor", json.dumps(actor_data, ensure_ascii=False), httponly=True)
                request.scope["actor"] = actor_data
                return response
            else:
                logger.warning("Login failed for user: %s", username)
                return Response.html(
                    await datasette.render_template(
                        "login.html",
                        {
                            "metadata": datasette.metadata(),
                            "error": "Invalid username or password"
                        },
                        request=request
                    )
                )
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return Response.html(
                await datasette.render_template(
                    "login.html",
                    {
                        "metadata": datasette.metadata(),
                        "error": f"Login error: {str(e)}"
                    },
                    request=request
                )
            )

    return Response.html(
        await datasette.render_template(
            "login.html",
            {"metadata": datasette.metadata()},
            request=request
        )
    )

async def register_page(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Register Cookies: {cookies}")

    if request.method == "POST":
        post_vars = await request.post_vars()
        logger.debug(f"Register POST vars: {post_vars}")
        username = post_vars.get("username")
        password = post_vars.get("password")
        if not username or not password:
            return Response.html(
                await datasette.render_template(
                    "register.html",
                    {
                        "metadata": datasette.metadata(),
                        "error": "Username and password are required"
                    },
                    request=request
                )
            )
        try:
            db = datasette.get_database("CAMPD")
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            await db.execute_write(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                [username, hashed_password]
            )
            logger.debug("User registered: %s", username)
            response = Response.redirect("/login")
            actor_data = {"id": username, "name": f"User {username}"}
            response.set_cookie("ds_actor", json.dumps(actor_data, ensure_ascii=False), httponly=True)
            request.scope["actor"] = actor_data
            return response
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            return Response.html(
                await datasette.render_template(
                    "register.html",
                    {
                        "metadata": datasette.metadata(),
                        "error": f"Registration error: {str(e)}"
                    },
                    request=request
                )
            )

    return Response.html(
        await datasette.render_template(
            "register.html",
            {"metadata": datasette.metadata()},
            request=request
        )
    )

async def logout_page(datasette, request):
    response = Response.redirect("/")
    response.set_cookie("ds_actor", "", expires=0)
    return response

async def admin_page(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    logger.debug(f"Admin Cookies: {cookies}")
    
    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = json.loads(ds_actor_cookie)
                logger.debug(f"Parsed actor from ds_actor cookie: {actor}")
                request.scope["actor"] = actor
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                actor = None

    logger.debug(f"Admin page access: actor={actor}")
    if not actor or actor.get("id") not in ["admin", "admin1", "admin2"]:
        logger.warning("Unauthorized admin access attempt")
        return Response.redirect("/login")

    db = datasette.get_database('CAMPD')
    sections = await db.execute('SELECT section, content FROM admin_content')
    content = {row['section']: json.loads(row['content']) for row in sections}

    # Parse markdown links for info and footer
    if 'info' in content and 'content' in content['info']:
        content['info']['paragraphs'] = parse_markdown_links(content['info']['content'])
    if 'footer' in content and 'content' in content['footer']:
        content['footer']['paragraphs'] = parse_markdown_links(content['footer']['content'])

    return Response.html(
        await datasette.render_template(
            'admin.html',
            {
                'content': content,
                'metadata': datasette.metadata(),
                'actor': actor,
                'success': request.args.get('success')
            },
            request=request
        )
    )

async def update_content(datasette, request):
    cookies = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', []) if k.decode('utf-8') == 'cookie'}
    actor = request.scope.get("actor")
    if not actor:
        cookie_string = cookies.get("cookie", "")
        ds_actor_cookie = None
        for cookie in cookie_string.split("; "):
            if cookie.startswith("ds_actor="):
                ds_actor_cookie = cookie[len("ds_actor="):]
                break
        if ds_actor_cookie:
            try:
                if ds_actor_cookie.startswith('"') and ds_actor_cookie.endswith('"'):
                    ds_actor_cookie = ds_actor_cookie[1:-1]
                ds_actor_cookie = ds_actor_cookie.replace('\\054', ',').replace('\\"', '"')
                actor = json.loads(ds_actor_cookie)
                logger.debug(f"Parsed actor from ds_actor cookie: {actor}")
                request.scope["actor"] = actor
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse ds_actor cookie: {e}, cookie value: {ds_actor_cookie}")
                actor = None

    logger.debug(f"Update content: actor={actor}")
    if not actor or actor.get("id") not in ["admin", "admin1", "admin2"]:
        logger.warning("Unauthorized update attempt")
        return Response.redirect("/login")

    db = datasette.get_database('CAMPD')
    section = None
    post_vars = {}
    files = {}

    # Handle multipart form data
    if 'multipart/form-data' in request.headers.get('content-type', '').lower():
        try:
            body = await request.post_body()
            content_type = request.headers.get('content-type', '')
            # Extract boundary manually from Content-Type header
            boundary = None
            if 'boundary=' in content_type.lower():
                boundary = content_type.split('boundary=')[-1].split(';')[0].strip().encode('utf-8')
            if not boundary:
                logger.error("No boundary found in Content-Type header")
                return Response.json({'error': 'Invalid multipart form data: missing boundary'}, status=400)

            # Parse multipart form data
            headers = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.scope.get('headers', [])}
            headers['content-type'] = content_type
            msg = BytesParser(policy=default).parsebytes(b'\r\n'.join([f'{k}: {v}'.encode('utf-8') for k, v in headers.items()]) + b'\r\n\r\n' + body)
            
            forms = {}
            files = {}

            for part in msg.iter_parts():
                if not part.is_multipart():
                    content_disposition = part.get('Content-Disposition', '')
                    if content_disposition:
                        disposition_params = {}
                        for param in content_disposition.split(';'):
                            param = param.strip()
                            if '=' in param:
                                key, value = param.split('=', 1)
                                disposition_params[key.strip()] = value.strip().strip('"')
                        field_name = disposition_params.get('name')
                        filename = disposition_params.get('filename')
                        if field_name:
                            if filename:
                                files[field_name] = {
                                    'filename': filename,
                                    'content': part.get_payload(decode=True)
                                }
                            else:
                                forms[field_name] = [part.get_payload(decode=True).decode('utf-8')]
            
            section = forms.get('section', [''])[0]
            logger.debug(f"Updating section: {section}")

            if section == 'header_image':
                # Get current header_image data from database
                current_content = {}
                result = await db.execute("SELECT content FROM admin_content WHERE section = ?", ["header_image"])
                row = result.first()
                if row:
                    try:
                        current_content = json.loads(row["content"])
                    except json.JSONDecodeError as e:
                        logger.error(f"JSON decode error for header_image: {str(e)}")
                        current_content = {}

                content = {
                    'image_url': current_content.get('image_url', '/static/header.jpg'),
                    'alt_text': sanitize_text(forms.get('alt_text', [''])[0]),
                    'credit_url': sanitize_text(forms.get('credit_url', [''])[0]),
                    'credit_text': sanitize_text(forms.get('credit_text', [''])[0])
                }

                if 'image' in files and files['image']['content']:
                    file = files['image']
                    if len(file['content']) > MAX_FILE_SIZE:
                        logger.error("File exceeds 5MB limit")
                        return Response.json({'error': 'File exceeds 5MB limit'}, status=400)
                    ext = Path(file['filename']).suffix.lower()
                    if ext not in ALLOWED_EXTENSIONS:
                        logger.error("Invalid file extension: %s", ext)
                        return Response.json({'error': 'Only .jpg and .png files allowed'}, status=400)
                    upload_dir = Path("static/uploads")
                    upload_dir.mkdir(parents=True, exist_ok=True)
                    filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
                    file_path = upload_dir / filename
                    with open(file_path, 'wb') as f:
                        f.write(file['content'])
                    content['image_url'] = f'/static/uploads/{filename}'
            else:
                # For non-file sections, use form data
                post_vars = {k: v[0] for k, v in forms.items()}
        except Exception as e:
            logger.error(f"Multipart form parsing error: {str(e)}")
            return Response.json({'error': f"Form parsing error: {str(e)}"}, status=400)
    else:
        # Handle regular form data for other sections
        post_vars = await request.post_vars()
        section = post_vars.get('section')
        logger.debug(f"Updating section: {section}")

    if section == 'title':
        content = {'content': sanitize_text(post_vars.get('content', ''))}

    elif section == 'info':
        content = {'content': sanitize_text(post_vars.get('content', ''))}

    elif section == 'feature_cards':
        cards = []
        i = 0
        while f'card_title_{i}' in post_vars:
            cards.append({
                'title': sanitize_text(post_vars[f'card_title_{i}']),
                'description': sanitize_text(post_vars[f'card_description_{i}']),
                'url': sanitize_text(post_vars[f'card_url_{i}']),
                'icon': 'ri-bar-chart-line'  # Static icon
            })
            i += 1
        content = cards

    elif section == 'statistics':
        stats = []
        i = 0
        while f'stat_label_{i}' in post_vars:
            query = post_vars[f'stat_query_{i}']
            if not query.startswith('SELECT COUNT(*) FROM emissions'):
                logger.error("Invalid SQL query: %s", query)
                return Response.json({'error': 'Invalid SQL query'}, status=400)
            stats.append({
                'label': sanitize_text(post_vars[f'stat_label_{i}']),
                'query': query,  # SQL query is not sanitized to preserve functionality
                'url': sanitize_text(post_vars[f'stat_url_{i}'])
            })
            i += 1
        content = stats

    elif section == 'footer':
        content = {
            'content': sanitize_text(post_vars.get('content', '')),
            'odbl_text': sanitize_text(post_vars.get('odbl_text', 'Data licensed under ODbL')),
            'odbl_url': sanitize_text(post_vars.get('odbl_url', 'https://opendatacommons.org/licenses/odbl/'))
        }

    else:
        logger.error("Invalid section: %s", section)
        return Response.json({'error': 'Invalid section'}, status=400)

    await db.execute_write(
        'INSERT OR REPLACE INTO admin_content (section, content, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)',
        (section, json.dumps(content, ensure_ascii=False))
    )
    logger.debug("Content updated successfully for section: %s", section)
    return Response.redirect('/admin?success=1')

async def index_page(datasette, request):
    db = datasette.get_database("CAMPD")

    async def get_section(section_name):
        result = await db.execute("SELECT content FROM admin_content WHERE section = ?", [section_name])
        row = result.first()
        if row:
            try:
                content = json.loads(row["content"])
                # Parse markdown links for info and footer
                if section_name == "info" and 'content' in content:
                    content['paragraphs'] = parse_markdown_links(content['content'])
                if section_name == "footer" and 'content' in content:
                    content['paragraphs'] = parse_markdown_links(content['content'])
                return content
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error for section {section_name}: {str(e)}")
                return {}
        else:
            return {}

    header_image = await get_section("header_image")
    info = await get_section("info")
    feature_cards = await get_section("feature_cards")
    statistics = await get_section("statistics")
    footer = await get_section("footer")
    title = await get_section("title")

    if isinstance(statistics, str):
        try:
            statistics = json.loads(statistics)
        except json.JSONDecodeError:
            logger.error("Failed to parse statistics JSON")
            statistics = []
    if not isinstance(statistics, list):
        statistics = []

    statistics_data = []
    for stat in statistics:
        query = stat.get("query", "")
        label = stat.get("label", "Unnamed Stat")
        url = stat.get("url", "")
        if query:
            try:
                result = await db.execute(query)
                value = result.first()[0] if result.first() else "N/A"
            except Exception as e:
                logger.error(f"Query error for stat {label}: {str(e)}")
                value = "Error"
        else:
            value = "N/A"
        statistics_data.append({"label": label, "value": value, "url": url})

    logger.debug(f"Rendering index with data: header_image={header_image}, info={info}, feature_cards={feature_cards}, statistics={statistics_data}, footer={footer}, title={title}")

    return Response.html(
        await datasette.render_template(
            "index.html",
            {
                "page_title": title.get('content', "EPA Clean Air Markets Program Data") + " | EDGI",
                "header_image": header_image,
                "info": info,
                "feature_cards": feature_cards,
                "statistics": statistics_data,
                "footer": footer,
                "content": {'title': title},  # Pass title in content for consistency
                "actor": request.scope.get("actor"),
                "debug": {
                    "header_image": header_image,
                    "info": info,
                    "feature_cards": feature_cards,
                    "statistics": statistics_data,
                    "footer": footer,
                    "title": title
                }
            },
            request=request
        )
    )

@hookimpl
def register_routes():
    return [
        (r"^/$", index_page),
        (r"^/login$", login_page),
        (r"^/register$", register_page),
        (r"^/logout$", logout_page),
        (r"^/admin$", admin_page),
        (r"^/admin/update$", update_content),
    ]