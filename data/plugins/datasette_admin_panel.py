import json
import bcrypt
import logging
from pathlib import Path
from datetime import datetime
from datasette import hookimpl
from datasette.utils.asgi import Response
from markupsafe import escape

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'.jpg', '.png'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

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
                response.set_cookie("ds_actor", json.dumps({"id": username, "name": f"User {username}"}), httponly=True)
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
            response.set_cookie("ds_actor", json.dumps({"id": username, "name": f"User {username}"}), httponly=True)
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
    actor = request.scope.get("actor")
    logger.debug(f"Admin page access: actor={actor}")
    if not actor or actor.get("id") != "admin":
        logger.warning("Unauthorized admin access attempt")
        return Response.redirect("/login")

    db = datasette.get_database('CAMPD')
    sections = await db.execute('SELECT section, content FROM admin_content')
    content = {row['section']: json.loads(row['content']) for row in sections}

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
    actor = request.scope.get("actor")
    logger.debug(f"Update content: actor={actor}")
    if not actor or actor.get("id") != "admin":
        logger.warning("Unauthorized update attempt")
        return Response.redirect("/login")

    db = datasette.get_database('CAMPD')
    post_vars = await request.post_vars()
    section = post_vars.get('section')
    logger.debug(f"Updating section: {section}")

    if section == 'header_image':
        if 'image' in request.files:
            file = request.files['image']
            if file.size > MAX_FILE_SIZE:
                logger.error("File exceeds 5MB limit")
                return Response.json({'error': 'File exceeds 5MB limit'}, status=400)
            ext = Path(file.filename).suffix.lower()
            if ext not in ALLOWED_EXTENSIONS:
                logger.error("Invalid file extension: %s", ext)
                return Response.json({'error': 'Only .jpg and .png files allowed'}, status=400)
            upload_dir = Path("static/uploads")
            upload_dir.mkdir(parents=True, exist_ok=True)
            filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
            file_path = upload_dir / filename
            with open(file_path, 'wb') as f:
                f.write(file.file.read())
            content = {
                'image_url': f'/static/uploads/{filename}',
                'alt_text': escape(post_vars.get('alt_text', '')),
                'credit_url': escape(post_vars.get('credit_url', '')),
                'credit_text': escape(post_vars.get('credit_text', ''))
            }
        else:
            logger.error("No image file provided")
            return Response.json({'error': 'No image file provided'}, status=400)

    elif section == 'info':
        paragraphs = []
        i = 0
        while f'paragraph_{i}' in post_vars:
            paragraphs.append(escape(post_vars[f'paragraph_{i}']))
            i += 1
        content = {'description': escape(post_vars.get('description', '')), 'paragraphs': paragraphs}

    elif section == 'feature_cards':
        cards = []
        i = 0
        while f'card_title_{i}' in post_vars:
            cards.append({
                'title': escape(post_vars[f'card_title_{i}']),
                'description': escape(post_vars[f'card_description_{i}']),
                'url': escape(post_vars[f'card_url_{i}']),
                'icon': escape(post_vars[f'card_icon_{i}'])
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
                'label': escape(post_vars[f'stat_label_{i}']),
                'query': query,
                'url': escape(post_vars[f'stat_url_{i}'])
            })
            i += 1
        content = stats

    elif section == 'footer':
        links = []
        i = 0
        while f'link_url_{i}' in post_vars:
            links.append({
                'url': escape(post_vars[f'link_url_{i}']),
                'text': escape(post_vars[f'link_text_{i}'])
            })
            i += 1
        content = {
            'icon': escape(post_vars.get('icon', '')),
            'text': escape(post_vars.get('text', '')),
            'links': links
        }

    else:
        logger.error("Invalid section: %s", section)
        return Response.json({'error': 'Invalid section'}, status=400)

    await db.execute_write(
        'INSERT OR REPLACE INTO admin_content (section, content, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)',
        (section, json.dumps(content))
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
                return json.loads(row["content"])
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

    # Ensure statistics is a list
    if isinstance(statistics, str):
        try:
            statistics = json.loads(statistics)
        except json.JSONDecodeError:
            logger.error("Failed to parse statistics JSON")
            statistics = []
    if not isinstance(statistics, list):
        statistics = []

    # Prepare statistics with computed values
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

    logger.debug(f"Rendering index with data: header_image={header_image}, info={info}, feature_cards={feature_cards}, statistics={statistics_data}, footer={footer}")

    return Response.html(
        await datasette.render_template(
            "index.html",
            {
                "page_title": "CAMPD (Clean Air Markets Program Data) | EDGI",
                "header_image": header_image,
                "info": info,
                "feature_cards": feature_cards,
                "statistics": statistics_data,
                "footer": footer,
                "metadata": datasette.metadata(),
                "actor": request.scope.get("actor"),
                "debug": {
                    "header_image": header_image,
                    "info": info,
                    "feature_cards": feature_cards,
                    "statistics": statistics_data,
                    "footer": footer
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

@hookimpl
def skip_csrf(scope):
    return scope["path"] in ["/login", "/register"]