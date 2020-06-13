# This module contains global urls for Kensa

from django.contrib import admin
from django.urls import path
from django.conf.urls import include, url
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.views import TokenObtainPairView
from DynamicAnalyzer.views.android import dynamic_analyzer as dz
from DynamicAnalyzer.views.android import (
    operations,
    report,
    tests_common,
    tests_frida
)

from Kensa import utils
from Kensa.views.api.views import (
    AppInfoView, 
    AppStoreView, 
    SecurityOverView, 
    MalwareOverView, 
    ComponentsActivities, 
    ComponentsServices, 
    ComponentsReceivers, 
    ComponentsProviders, 
    ComponentsLibraries, 
    ComponentsFiles, 
    DomainAnalysis, 
    APKIDAnalysis, 
    ManifestAnalysis, 
    CodeAnalysis, 
    BinaryAnalysis, 
    FileAnalysis, 
    AppPermissions, 
    JavaCodeView, 
    SmaliCodeView, 
    ReconEmailsView, 
    ReconFirebasedbURLsView, 
    ReconURLsView, 
    ReconTrackersView, 
    ReconStringsView,
    UploadAppView, 
    ScanAppView,
    DeleteScanView,
    GetRecentScansView,
    GetSignerCertificateView,
    GetManifestView,
    GetDomainsDataView,
    GetSearchView,
    PDFReportView, 
    JSONReportView,
    SourceView
)
from Kensa.views import home

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
    path('admin/', admin.site.urls),
    path('accounts/login', TokenObtainPairView.as_view(), name='kensa_token_obtain_pair'),
    path('accounts/token/fresh', TokenRefreshView.as_view(), name='token_refresh'),

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
    url(r'^StaticAnalyzer/$', android_sa.static_analyzer_android),
    url(r'^ViewSource/$', view_source.run),
    url(r'^Smali/$', smali.run),
    url(r'^Java/$', java.run),
    url(r'^Find/$', find.run),
    url(r'^generate_downloads/$', generate_downloads.run),
    url(r'^ManifestView/$', manifest_view.run),
    
    # IOS
    # url(r'^StaticAnalyzer_iOS/$', ios_sa.static_analyzer_ios),
    url(r'^ViewFile/$', io_view_source.run),
    
    # Windows
    url(r'^StaticAnalyzer_Windows/$', windows.staticanalyzer_windows),
    # Shared
    url(r'^PDF/$', shared_func.pdf),
    # App Compare
    url(r'^compare/(?P<hash1>[0-9a-f]{32})/(?P<hash2>[0-9a-f]{32})/$',
        shared_func.compare_apps),
    
    # Dynamic Analysis
    url(r'^dynamic_analysis/$',dz.dynamic_analysis, name='dynamic'),
    url(r'^android_dynamic/$', dz.dynamic_analyzer, name='dynamic_analyzer'),
    url(r'^httptools$',dz.httptools_start, name='httptools'),
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
    url(r'^api/v1/upload$', UploadAppView.as_view()),
    url(r'^api/v1/scan$', ScanAppView.as_view()),
    url(r'^api/v1/delete_scan$', DeleteScanView.as_view()),
    url(r'^api/v1/download_pdf$', PDFReportView.as_view()),
    url(r'^api/v1/report_json$', JSONReportView.as_view()),
    url(r'^api/v1/view_source$', SourceView.as_view()),
    
    url(r"^api/v1/recent_scans$", GetRecentScansView.as_view()),
    url(r"^api/v1/signer_certificate$", GetSignerCertificateView.as_view()),
    url(r"^api/v1/code/manifest$", GetManifestView.as_view()),
    url(r"^api/v1/summary/domain_analysis_country$", GetDomainsDataView.as_view()),
    url(r"^api/v1/code/java$", JavaCodeView.as_view()),
    url(r"^api/v1/code/smali$", SmaliCodeView.as_view()),
    url(r"^api/v1/api_md5_search$", GetSearchView.as_view()),
    url(r"^api/v1/recon_emails$", ReconEmailsView.as_view()),
    url(r"^api/v1/recon_firebase$", ReconFirebasedbURLsView.as_view()),
    url(r"^api/v1/recon_urls$", ReconURLsView.as_view()),
    url(r"^api/v1/recon_trackers$", ReconTrackersView.as_view()),
    url(r"^api/v1/recon_strings$", ReconStringsView.as_view()),

    # Class Based View
    url(r'^api/v1/app_info$', AppInfoView.as_view()),
    url(r'^api/v1/appstore_info$', AppStoreView.as_view()),
    url(r'^api/v1/summary/security_overview$', SecurityOverView.as_view()),
    url(r'^api/v1/summary/malware_overview$', MalwareOverView.as_view()),
    url(r'^api/v1/summary/components/activities$', ComponentsActivities),
    url(r'^api/v1/summary/components/services$', ComponentsServices),
    url(r'^api/v1/summary/components/receivers$', ComponentsReceivers),
    url(r'^api/v1/summary/components/providers$', ComponentsProviders),
    url(r'^api/v1/summary/components/libraries$', ComponentsLibraries),
    url(r'^api/v1/summary/components/files$', ComponentsFiles),

    url(r'^api/v1/summary/domain_analaysis$', DomainAnalysis),
    url(r'^api/v1/malware_analysis/apk_id', APKIDAnalysis),
    url(r'^api/v1/security_analysis/manifest_analysis$', ManifestAnalysis),
    url(r'^api/v1/security_analysis/code_analysis$', CodeAnalysis),
    url(r'^api/v1/security_analysis/binary_analysis$', BinaryAnalysis),
    url(r'^api/v1/security_analysis/file_analysis$', FileAnalysis),
    url(r'^api/v1/security_analysis/app_permissions$', AppPermissions),

    # Test
    url(r'^tests/$', tests.start_test),
    
]

utils.print_version()
