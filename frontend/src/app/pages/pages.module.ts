import { NgModule } from '@angular/core';
import { NbMenuModule,NbRouteTabsetModule } from '@nebular/theme';

import { ThemeModule } from '../@theme/theme.module';
import { PagesComponent } from './pages.component';
import { SummaryModule } from './summary/summary.module';
import { HomeModule } from './home/home.module';
import { SecurityModule } from './security/security.module';
import { SupportModule } from './support/support.module';
import { AboutModule } from './about/about.module';
import { ApiModule } from './api/api.module';
import { MalwareModule } from './malware/malware.module';

import { PagesRoutingModule } from './pages-routing.module';
import { MiscellaneousModule } from './miscellaneous/miscellaneous.module';

@NgModule({
  imports: [
    PagesRoutingModule,
    ThemeModule,
    NbMenuModule,
    SummaryModule,
    HomeModule,
    MiscellaneousModule,
    NbRouteTabsetModule,
    SupportModule,
    AboutModule,
    ApiModule,
  ],
  declarations: [
    PagesComponent,
  ],
})
export class PagesModule {
}
