from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django import forms
from django.contrib.auth.models import Permission
from django.contrib.auth.models import User, Group
from django.contrib.auth.admin import GroupAdmin
from django.contrib.auth.forms import UserChangeForm

from .models import User
MODELS_TO_HIDE_STD_PERMISSIONS = (
    ("Kensa", "contenttypes"),
)




class UserAdmin(BaseUserAdmin):
    admin.site.site_title = 'Kensa'
    admin.site.site_header = 'Kensa Administration'
    admin.site.site_title = 'Kensa Administration'
    fieldsets = (
        (None, {'fields': ('email', 'password', 'first_name', 'last_name', 'short_name', 'organization', 'last_login')}),
        ('Permissions', {'fields': (
            'is_active',
            'is_staff',
            'is_admin',
            'is_superuser',
            'groups',
            'user_permissions',
        )}),
    )
    add_fieldsets = (
        (
            None,
            {
                'classes': ('wide',),
                'fields': ('email', 'password1', 'password2','organization')
            }
        ),
    )

    list_display = ('email', 'name', 'is_staff','is_admin', 'first_name', 'last_name', 'short_name', 'organization', 'last_login')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('email',)
    ordering = ('email',)
    filter_horizontal = ('groups', 'user_permissions',)


admin.site.register(User, UserAdmin)
class PermissionFilterMixin(object):
    def formfield_for_manytomany(self, db_field, request=None, **kwargs):
        if db_field.name in ('permissions', 'user_permissions'):
            qs = kwargs.get('queryset', db_field.remote_field.model.objects)
            qs = _filter_permissions(qs)
            kwargs['queryset'] = qs

        return super(PermissionFilterMixin, self).formfield_for_manytomany(db_field, request, **kwargs)


class MyGroupAdmin(PermissionFilterMixin, GroupAdmin):
    pass


class MyUserAdmin(PermissionFilterMixin, UserAdmin):
    pass


admin.site.unregister(User)
admin.site.unregister(Group)
admin.site.register(User, MyUserAdmin)
admin.site.register(Group, MyGroupAdmin)


def _filter_permissions(qs):
    return qs.exclude(codename__in=(


        'add_contenttype',
        'change_contenttype',
        'delete_contenttype',
        'view_contenttype',

        'add_session',
        'delete_session',
        'change_session',
        'view_session',

        # django.contrib.admin
        'add_logentry',
        'change_logentry',
        'delete_logentry',
        'view_logentry',

        'add_kensa',
        'change_kensa',
        'delete_kensa',
        'view_kensa',


        'add_site',
        'change_site',
        'delete_site',
        'view_site',

        'add_emailconfirmation',
        'change_emailconfirmation',
        'delete_emailconfirmation',
        'view_emailconfirmation',


        'add_staticanalyzer',
        'change_staticanalyzer',
        'delete_staticanalyzer',
        'view_staticanalyzer',

        'add_staticanalyzerios',
        'change_staticanalyzerios',
        'delete_staticanalyzerios',
        'view_staticanalyzerios',


        'add_staticanalyzerandroid',
        'change_staticanalyzerandroid',
        'delete_staticanalyzerandroid',
        'view_staticanalyzerandroid',

        'add_staticanalyzerwindows',
        'change_staticanalyzerwindows',
        'delete_staticanalyzerwindows',
        'view_staticanalyzerwindows',


        'add_recentscansdb',
        'change_recentscansdb',
        'delete_recentscansdb',
        'view_recentscansdb',


        # south
        'add_migrationhistory',
        'change_migrationhistory',
        'delete_migrationhistory',

        # django-admin-tools
        'add_dashboardpreferences',
        'change_dashboardpreferences',
        'delete_dashboardpreferences',

        'add_bookmark',
        'change_bookmark',
        'delete_bookmark',
    )) \
    .exclude(codename__endswith='userobjectpermission') \
    .exclude(codename__endswith='groupobjectpermission')  # django-guardian
