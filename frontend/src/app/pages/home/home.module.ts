import { NgModule } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { RecentScanService } from '../../@core/utils/recent-scans';
import { RouterModule } from '@angular/router';

import {
  NbActionsModule,
  NbButtonModule,
  NbCardModule,
  NbTabsetModule,
  NbUserModule,
  NbRadioModule,
  NbSelectModule,
  NbListModule,
  NbIconModule,

} from '@nebular/theme';
import { NgxChartsModule } from '@swimlane/ngx-charts';
import { ThemeModule } from '../../@theme/theme.module';
import { HomeComponent } from './home.component';
import { RecentScanComponent } from './recent-scan/recent-scan.component';
@NgModule({
  imports: [
    ThemeModule,
    NbCardModule,
    NbUserModule,
    NbButtonModule,
    NbTabsetModule,
    NbActionsModule,
    NbRadioModule,
    NbSelectModule,
    NbListModule,
    NbIconModule,
    NbButtonModule,
    NgxChartsModule,
    MatIconModule,
    RouterModule,
  ],
  declarations: [
    HomeComponent,
    RecentScanComponent,
  ],
  providers: [
    RecentScanService,
  ]
})
export class HomeModule {
}
