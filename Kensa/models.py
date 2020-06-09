from django.db import models

class Kensa(models.Model):
    class Meta:
        permissions = [
            ("can_view_recent_scans","Can view recent scans"),
            ("can_delete_recent_scans", "can delete recent scans"),
            ("can_upload","Can upload"),

        ]
