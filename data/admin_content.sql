CREATE TABLE IF NOT EXISTS admin_content (
    id INTEGER PRIMARY KEY,
    section TEXT NOT NULL,
    content JSON NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Initialize with default content mirroring index.html
INSERT OR REPLACE INTO admin_content (section, content) VALUES
('header_image', '{
    "image_url": "/static/header.jpg",
    "alt_text": "CAMPD Header by J. Alex Lang",
    "credit_url": "https://www.flickr.com/photos/jalexlang/21359307802/",
    "credit_text": "Image by J. Alex Lang. Used by permission."
}'),
('info', '{
    "description": "The EPA’s Clean Air Markets Program Data (CAMPD) provides emissions, compliance, allowance, and facility attributes data collected under programs like the Acid Rain Program and Cross-State Air Pollution Rule.",
    "paragraphs": [
        "This project, maintained by EDGI, serves as a virtual backup of CAMPD data, hosted on Zenodo and powered by Datasette. It includes hourly and daily emissions data, accessible for download or interactive exploration. The dataset is licensed under the ODbL.",
        "Our code is open source. The archived data and code can be found at <a href=\"https://github.com/willf/datasette-campd\" class=\"text-accent hover:text-primary\">EDGI GitHub</a>. Explore the data interactively at <a href=\"https://datasette.io/\" class=\"text-accent hover:text-primary\">Datasette</a> or access the original data at <a href=\"https://campd.epa.gov/\" class=\"text-accent hover:text-primary\">EPA Clean Air Markets Program Data (CAMPD)</a> and <a href=\"https://zenodo.org/communities/edgi/records?q=campd&l=list&p=1&s=10&sort=bestmatch\" class=\"text-accent hover:text-primary\">Zenodo</a>.",
        "Contact us at <a href=\"mailto:campd-support@camdsupport.com\" class=\"text-accent hover:text-primary\">contact@envirodatagov.org</a> for support or inquiries."
    ]
}'),
('feature_cards', '[
    {
        "title": "Emissions Data",
        "description": "Browse hourly and daily emissions data from power plants, including file descriptions and download links.",
        "url": "/CAMPD/emissions",
        "icon": "ri-bar-chart-line"
    },
    {
        "title": "Data Archive",
        "description": "Access CAMPD emissions data on Zenodo to explore locally with Datasette or other tools.",
        "url": "https://zenodo.org/communities/edgi/records?q=campd&l=list&p=1&s=10&sort=bestmatch",
        "icon": "ri-bar-chart-line"
    },
    {
        "title": "CAM API Portal",
        "description": "Access CAMPD data programmatically via the EPA’s REST API.",
        "url": "https://www.epa.gov/airmarkets/cam-api-portal",
        "icon": "ri-bar-chart-line"
    }
]'),
('statistics', '[
    {
        "label": "Total Files",
        "query": "SELECT COUNT(*) FROM emissions",
        "url": "/CAMPD/emissions"
    },
    {
        "label": "Hourly Files",
        "query": "SELECT COUNT(*) FROM emissions WHERE unit = ''hourly''",
        "url": "/CAMPD/emissions?unit=hourly"
    },
    {
        "label": "Daily Files",
        "query": "SELECT COUNT(*) FROM emissions WHERE unit = ''daily''",
        "url": "/CAMPD/emissions?unit=daily"
    }
]'),
('footer', '{
    "icon": "ri-earth-line",
    "text": "Made with <span class=\"text-red-500\" aria-label=\"love\">❤</span> by",
    "links": [
        {"url": "https://envirodatagov.org", "text": "EDGI"},
        {"url": "https://screening-tools.com/", "text": "Public Environmental Data Partners"}
    ]
}');