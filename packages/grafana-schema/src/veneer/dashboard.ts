
import * as raw from "../schema/dashboard/dashboard.gen";

export interface Dashboard extends raw.Dashboard {
  panels?: Array<Panel | raw.RowPanel | {
    type: 'graph';
  } | {
    type: 'heatmap';
  }>;
}

export interface Panel<TOptions = Record<string, unknown>, TCustomFieldConfig = Record<string, unknown>> extends raw.Panel {
  fieldConfig: FieldConfigSource<TCustomFieldConfig>
}

export interface FieldConfig<TOptions = Record<string, unknown>> extends raw.FieldConfig {
  custom?: TOptions;
}

export interface FieldConfigSource<TOptions = Record<string, unknown>> extends raw.FieldConfigSource {
  defaults: FieldConfig<TOptions>;
}
