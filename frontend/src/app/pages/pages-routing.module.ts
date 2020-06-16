import { RouterModule, Routes } from '@angular/router';
import { NgModule } from '@angular/core';
import { AuthGuard } from '../auth-guard.service';

import { PagesComponent } from './pages.component';
import { SummaryComponent } from './summary/summary.component';
import { HomeComponent } from './home/home.component';
import { SecurityComponent } from './security/security.component';
import { MaintenanceComponent } from './maintenance/maintenance.component';
import { SupportComponent } from './support/support.component';
import { ApiComponent } from './api/api.component';
import { AboutComponent } from './about/about.component';
import { MalwareComponent } from './malware/malware.component';

import { NotFoundComponent } from './miscellaneous/not-found/not-found.component';

const routes: Routes = [{
  path: '',
  component: PagesComponent,
  children: [
    {
      path: 'home',
      canActivate: [AuthGuard],
      component: HomeComponent,
    },
    {
      path: 'summary/:id',
      canActivate: [AuthGuard],
      component: SummaryComponent,
    },
    {
      path: 'security/:id',
      canActivate: [AuthGuard],
      component: SecurityComponent,
    },

    {
      path: 'malware/:id',
      canActivate: [AuthGuard],
      component: MalwareComponent,
    },

    {
      path: 'team',
      canActivate: [AuthGuard],
      component: MaintenanceComponent,
    },
    {
      path: 'profile',
      canActivate: [AuthGuard],
      component: MaintenanceComponent,
    },
    {
      path: 'support',
      //canActivate: [AuthGuard],
      component: SupportComponent,
    },

        {
          path: 'about',
          //canActivate: [AuthGuard],
          component: AboutComponent,
        },

            {
              path: 'api',
              //canActivate: [AuthGuard],
              component: ApiComponent,
            },
    {
      path: '',
      redirectTo: 'home',
      pathMatch: 'full',
    },
    {
      path: '**',
      component: NotFoundComponent,
    },
  ],
}];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class PagesRoutingModule {
}
