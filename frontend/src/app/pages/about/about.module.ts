import { NgModule } from '@angular/core';
import { ThemeModule } from '../../@theme/theme.module';
import { AboutComponent } from './about.component';

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
  ],
  declarations: [
    AboutComponent,
  ],
  providers: [
  ]
})
export class AboutModule {
}
