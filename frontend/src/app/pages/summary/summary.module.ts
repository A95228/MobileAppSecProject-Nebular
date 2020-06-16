import { NgModule } from '@angular/core';
import { NgxEchartsModule } from 'ngx-echarts';
import { NgxChartsModule } from '@swimlane/ngx-charts';
import { MatIconModule } from '@angular/material/icon';
import { CountryDomainsComponent } from './country-domains/country-domains.component';
import { LeafletModule } from '@asymmetrik/ngx-leaflet';
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
import { ThemeModule } from '../../@theme/theme.module';
import { SummaryComponent } from './summary.component';
import { TopAppInfoModule } from '../top-app-info/top-app-info.module';

@NgModule({
  imports: [
    ThemeModule,
    TopAppInfoModule,
    MatIconModule,
    NbCardModule,
    LeafletModule,
    NgxEchartsModule,
    NgxChartsModule,

  ],
  declarations: [
    SummaryComponent,
    CountryDomainsComponent,
  ],
  providers: [
  ],
})
export class SummaryModule {
}
