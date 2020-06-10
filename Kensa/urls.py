from django.contrib import admin
from django.urls import path
from django.conf.urls import include, url
from DynamicAnalyzer.views.android import dynamic_analyzer as dz
from DynamicAnalyzer.views.android import (
    operations,
    report,
    tests_common,
    tests_frida)

from Kensa import utils
from Kensa.views import home
from Kensa.views.api import rest_api

from StaticAnalyzer import tests
from StaticAnalyzer.views import shared_func
from StaticAnalyzer.views.android import (
    find,
    generate_downloads,
    java,
    manifest_view,
    smali,
    view_source,
)
from StaticAnalyzer.views.windows import windows
from StaticAnalyzer.views.android import static_analyzer as android_sa
from StaticAnalyzer.views.ios import static_analyzer as ios_sa
from StaticAnalyzer.views.ios import view_source as io_view_source

urlpatterns = [

    # General
    url(r'^$', home.index, name='home'),
    path('grappelli/', include('grappelli.urls')), # grappelli URLS
    path('admin/', admin.site.urls),
    path('accounts/', include('allauth.urls')),

    url(r'^upload/$', home.Upload.as_view),
    url(r'^download/', home.download),
    url(r'^about$', home.about, name='about'),
    url(r'^api_docs$', home.api_docs, name='api_docs'),
    url(r'^recent_scans/$', home.recent_scans, name='recent'),
    url(r'^delete_scan/$', home.delete_scan),
    url(r'^search$', home.search),
    url(r'^error/$', home.error, name='error'),
    url(r'^not_found/$', home.not_found),
    url(r'^zip_format/$', home.zip_format),
    url(r'^mac_only/$', home.mac_only),

    # Android
    url(r'^StaticAnalyzer/$', android_sa.static_analyzer),
    url(r'^ViewSource/$', view_source.run),
    url(r'^Smali/$', smali.run),
    url(r'^Java/$', java.run),
    url(r'^Find/$', find.run),
    url(r'^generate_downloads/$', generate_downloads.run),
    url(r'^ManifestView/$', manifest_view.run),

    # IOS
    url(r'^StaticAnalyzer_iOS/$', ios_sa.static_analyzer_ios),
    url(r'^ViewFile/$', io_view_source.run),

    # Windows
    url(r'^StaticAnalyzer_Windows/$', windows.staticanalyzer_windows),

    # Shared
    url(r'^PDF/$', shared_func.pdf),

    # App Compare
    url(r'^compare/(?P<hash1>[0-9a-f]{32})/(?P<hash2>[0-9a-f]{32})/$',
        shared_func.compare_apps),

    # Dynamic Analysis
    url(r'^dynamic_analysis/$',
        dz.dynamic_analysis,
        name='dynamic'),
    url(r'^android_dynamic/$',
        dz.dynamic_analyzer,
        name='dynamic_analyzer'),
    url(r'^httptools$',
        dz.httptools_start,
        name='httptools'),
    url(r'^logcat/$', dz.logcat),

    # Android Operations
    url(r'^kensay/$', operations.kensay),
    url(r'^screenshot/$', operations.take_screenshot),
    url(r'^execute_adb/$', operations.execute_adb),
    url(r'^screen_cast/$', operations.screen_cast),
    url(r'^touch_events/$', operations.touch),
    url(r'^get_component/$', operations.get_component),
    url(r'^kensa_ca/$', operations.kensa_ca),

    # Dynamic Tests
    url(r'^activity_tester/$', tests_common.activity_tester),
    url(r'^download_data/$', tests_common.download_data),
    url(r'^collect_logs/$', tests_common.collect_logs),

    # Frida
    url(r'^frida_instrument/$', tests_frida.instrument),
    url(r'^live_api/$', tests_frida.live_api),
    url(r'^frida_logs/$', tests_frida.frida_logs),
    url(r'^list_frida_scripts/$', tests_frida.list_frida_scripts),
    url(r'^get_script/$', tests_frida.get_script),

    # Report
    url(r'^dynamic_report/$', report.view_report),
    url(r'^dynamic_view_file/$', report.view_file),

    # REST API
    url(r'^api/v1/upload$', rest_api.api_upload),
    url(r'^api/v1/scan$', rest_api.api_scan),
    url(r'^api/v1/delete_scan$', rest_api.api_delete_scan),
    url(r'^api/v1/download_pdf$', rest_api.api_pdf_report),
    url(r'^api/v1/report_json$', rest_api.api_json_report),
    url(r'^api/v1/view_source$', rest_api.api_view_source),
    url(r'^api/v1/scans$', rest_api.api_recent_scans),

    url(r"^api/v1/recent_scans$", rest_api.api_get_recent_scans),
    url(r"^api/v1/signer_certificate$",rest_api.api_get_signer_certificate),
    url(r"^api/v1/code/manifest$", rest_api.api_get_manifest),
    url(r"^api/v1/summary/domain_analysis_country$", rest_api.api_get_domains_data),
    url(r"^api/v1/code/java$", rest_api.api_get_java_code),
    url(r"^api/v1/code/smali$", rest_api.api_get_smali_code),

    # REST API Reconnaissance Routes
    url(r"^api/v1/recon_emails$", rest_api.api_get_recon_emails),
    url(r"^api/v1/recon_firebase$", rest_api.api_get_recon_firebase_db_urls),
    url(r"^api/v1/recon_urls$", rest_api.api_get_recon_urls),
    url(r"^api/v1/recon_trackers$", rest_api.api_get_recon_trackers),
    url(r"^api/v1/recon_strings$", rest_api.api_get_recon_strings),
    
    # API Search Route
    url(r"^api/v1/api_md5_search$", rest_api.api_get_search),

    # Test
    url(r'^tests/$', tests.start_test),
    
]

utils.print_version()
