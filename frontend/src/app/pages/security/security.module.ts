import { NgModule} from '@angular/core';
import {MatIconModule} from '@angular/material/icon';
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
import { SecurityComponent } from './security.component';
import { TopAppInfoModule } from '../top-app-info/top-app-info.module';
import {MatTableModule} from '@angular/material/table';

@NgModule({
  imports: [
    ThemeModule,
    TopAppInfoModule,
    MatIconModule,
    NbCardModule,
    NbTabsetModule,
    MatTableModule,
    NbSelectModule,

  ],
  declarations: [
    SecurityComponent,
    
  ],
  providers: [
],
})

export class SecurityModule {

}
