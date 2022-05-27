import React from 'react';

import { IconName, ToolbarButton } from '@grafana/ui';

import { SceneComponentProps, SceneItemBase } from './SceneItem';

export interface ToolbarButtonState {
  icon: IconName;
  onClick: () => void;
}

export class SceneToolbarButton extends SceneItemBase<ToolbarButtonState> {
  Component = ({ model }: SceneComponentProps<SceneToolbarButton>) => {
    const state = model.useState();

    return <ToolbarButton onClick={state.onClick} icon={state.icon} />;
  };
}

export interface ScenePanelSize {
  width: number;
  height: number;
}