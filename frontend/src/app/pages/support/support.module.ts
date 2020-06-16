import { NgModule } from '@angular/core';
import { ThemeModule } from '../../@theme/theme.module';
import { SupportComponent } from './support.component';

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

@NgModule({
  imports: [
    ThemeModule,
    NbCardModule,
    NbUserModule,
  ],
  declarations: [
    SupportComponent,
  ],
  providers: [
  ]
})
export class SupportModule {
}
